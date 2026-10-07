//! social67-node: the headless 67Social storage node daemon.
//!
//! The durable node of the network — the same shared core as the app, no
//! UI. It joins the gossip topic, mirrors records, serves ciphertext blobs
//! to any authorized peer, and holds replicas. It never sees plaintext.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use iroh::EndpointId;
use social67_core::feed::FeedEvent;
use social67_core::net::Invite;
use social67_core::session::{fresh_topic, Session, SessionEvent};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "social67-node", about = "67Social headless storage node")]
struct Args {
    /// Data directory (identity, blob store, record log).
    #[arg(long, default_value = "./social67-node-data")]
    data_dir: PathBuf,

    /// Handle for this node's directory entry.
    #[arg(long, default_value = "node")]
    handle: String,

    /// Display name.
    #[arg(long)]
    display_name: Option<String>,

    /// Invite string from another node (topic + peer endpoint). Without
    /// one, a fresh topic is created and this node starts a new network.
    #[arg(long)]
    invite: Option<String>,

    /// Demo: publish an image file once at startup (goes through the full
    /// ingest → encrypt → blob → gossip pipeline).
    #[arg(long)]
    demo_post: Option<PathBuf>,

    /// Demo post caption.
    #[arg(long, default_value = "posted from the node")]
    demo_caption: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("social67=info".parse()?))
        .init();

    let args = Args::parse();
    let display = args.display_name.unwrap_or_else(|| args.handle.clone());

    let (topic, bootstrap, inviter_addr) = match &args.invite {
        Some(raw) => {
            let invite = Invite::decode(raw).context("decoding invite")?;
            info!(topic = %invite.topic, peer = %invite.node_id(), "joining network from invite");
            (invite.topic, vec![invite.node_id()], Some(invite.addr))
        }
        None => {
            let topic = fresh_topic();
            info!(topic = %topic, "starting a new network topic");
            (topic, vec![], None)
        }
    };

    let mut session = Session::start(
        args.data_dir.clone(),
        &args.handle,
        &display,
        topic,
        bootstrap,
    )
    .await
    .context("starting session")?;

    info!(
        root = %session.identity.root_pub()?,
        endpoint = %session.node.node_id(),
        "node up"
    );
    println!("\n  invite: {}\n", session.invite().encode());

    // Dial the inviter directly and mesh in gossip.
    if let Some(addr) = inviter_addr {
        let id = addr.id;
        session.add_peer_addr(addr);
        session.join_gossip_peer(id).await?;
    }

    // Demo publish through the full pipeline.
    if let Some(path) = &args.demo_post {
        let bytes = std::fs::read(path).context("reading --demo-post file")?;
        let id = session
            .create_post(&bytes, &args.demo_caption, social67_core::records::Audience::Public)
            .await?;
        info!(post = ?id, "demo post published (public)");
    }

    // Extra peers to mesh with, learned from directory entries as they
    // arrive — keeps the swarm connected without a central rendezvous.
    let mut meshed: Vec<EndpointId> = vec![];

    loop {
        session.pump().await;

        // Drain events into the log.
        let events: Vec<SessionEvent> = session.events.drain(..).collect();
        for ev in events {
            match ev {
                SessionEvent::Feed(FeedEvent::PostAdded { post_id }) => {
                    info!(post = ?post_id, "post record received");
                }
                SessionEvent::Feed(FeedEvent::PostUnlinked { post_id }) => {
                    info!(post = ?post_id, "post unlinked (crypto-shredded)");
                }
                SessionEvent::Feed(FeedEvent::DirectoryUpdated { root }) => {
                    info!(root = %root, "directory entry updated");
                    // Mesh with newly discovered serving nodes.
                    if let Some(entry) = session.feed.directory.get(&root) {
                        for s in &entry.serving_nodes {
                            if let Ok(id) = EndpointId::from_str(s) {
                                if id != session.node.node_id() && !meshed.contains(&id) {
                                    meshed.push(id);
                                    let _ = session.join_gossip_peer(id).await;
                                }
                            }
                        }
                    }
                }
                SessionEvent::Feed(FeedEvent::FollowRequest { from }) => {
                    info!(from = %from, "follow request pending");
                }
                SessionEvent::Feed(FeedEvent::MessageRequest { from }) => {
                    info!(from = %from, "message request pending");
                }
                SessionEvent::ChatReceived { from, .. } => {
                    info!(from = %from, "chat message (not stored — ephemeral)");
                }
                SessionEvent::Feed(FeedEvent::GovernanceApplied) => {
                    info!("governance record applied");
                }
                _ => {}
            }
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
