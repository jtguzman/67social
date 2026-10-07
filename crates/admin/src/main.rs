//! social67-admin: the operator tool.
//!
//! Two separate powers, kept separate (see the design document):
//! - `govern`: sign and publish suspension / blocklist / handle-binding
//!   records. Never touches a photo.
//! - `case`: per-user escrow read for compliance — fetch ciphertext like
//!   any authorized reader, unwrap offline with the user's escrow key,
//!   log every access to the append-only audit log.
//!
//! Honest limits, restated: no global master key (cases are per-user);
//! time-boxing needs the custody mediator (not built); chat is not
//! retrievable by anyone.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use social67_core::admin::{
    pin_admin_key, publish_governance, run_case, AdminIdentity, AuditLog,
};
use social67_core::keys::{EscrowIdentity, PubKey};
use social67_core::net::Invite;
use social67_core::records::GovernanceAction;
use social67_core::session::{fresh_topic, Session};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "social67-admin", about = "67Social operator tool")]
struct Args {
    /// Operator data dir (admin key, audit log, node state).
    #[arg(long, default_value = "./social67-admin-data")]
    data_dir: PathBuf,

    /// Invite string of the network to operate on. Without one, a fresh
    /// topic is used (only useful for keygen/testing).
    #[arg(long)]
    invite: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate (or load) the admin/governance key and print its public key.
    Keygen,
    /// Publish a governance record. Clients enforce it via signature.
    Govern {
        #[command(subcommand)]
        action: GovernAction,
    },
    /// Open a case: read one user's content via their escrow key, with a
    /// full audit trail. Requires the user's escrow key file.
    Case {
        /// Target user's root key (hex).
        #[arg(long)]
        user_root: String,
        /// Path to the user's escrow private key (hex file). In production
        /// this lives with the custody mediator until a case opens.
        #[arg(long)]
        escrow_key: PathBuf,
        /// Where decrypted case material is written.
        #[arg(long, default_value = "./case-output")]
        out: PathBuf,
        /// Case reference for the audit log.
        #[arg(long, default_value = "unreferenced")]
        case_ref: String,
        /// Seconds to sync records over gossip before reading.
        #[arg(long, default_value = "20")]
        sync_secs: u64,
    },
    /// Print the audit log's chain head hash and verify the chain.
    Audit,
}

#[derive(Subcommand)]
enum GovernAction {
    /// Suspend an account: clients refuse to sync/display its content.
    Suspend {
        #[arg(long)]
        root: String,
        #[arg(long, default_value = "policy violation")]
        reason: String,
    },
    /// Lift a suspension.
    Reinstate { #[arg(long)] root: String },
    /// Blocklist a content hash (illegal material); nodes drop the blob.
    Blocklist {
        #[arg(long)]
        hash: String,
        #[arg(long, default_value = "illegal content")]
        reason: String,
    },
    /// Registrar: settle @handle ties, binding handle → root key.
    BindHandle {
        #[arg(long)]
        handle: String,
        #[arg(long)]
        root: String,
    },
}

fn parse_root(s: &str) -> Result<PubKey> {
    PubKey::from_str(s).context("bad root key hex")
}

fn parse_escrow_key(path: &PathBuf) -> Result<EscrowIdentity> {
    let raw = std::fs::read_to_string(path)?;
    let hex = raw.trim();
    let bytes = data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .map_err(|e| anyhow!("bad escrow key hex: {e}"))?;
    Ok(EscrowIdentity::from_bytes(&bytes)?)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("social67=info".parse()?))
        .init();

    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;

    let admin = AdminIdentity::load(&args.data_dir.join("admin.json"))
        .or_else(|_| {
            let a = AdminIdentity::generate();
            a.save(&args.data_dir.join("admin.json"))?;
            Ok::<_, anyhow::Error>(a)
        })
        .context("loading admin key")?;
    println!("admin public key: {}", admin.admin_pub());

    match &args.command {
        Command::Keygen => {
            println!("admin key (private): {}", args.data_dir.join("admin.json").display());
            // Write the pin file here too — copy it (just this line) to
            // every node's data dir as admin.pub.
            pin_admin_key(&args.data_dir, &admin.admin_pub())?;
            println!("pinned in {} — copy this file to every node's data dir:", args.data_dir.join("admin.pub").display());
            println!("  {}", admin.admin_pub());
            return Ok(());
        }
        Command::Audit => {
            let log = AuditLog::open(args.data_dir.join("audit.jsonl"), admin.admin_pub())?;
            match log.verify() {
                Ok(()) => println!(
                    "chain OK — {} entries, head hash:\n  {}",
                    log.entries().len(),
                    data_encoding::HEXLOWER.encode(&log.chain_head())
                ),
                Err(e) => {
                    eprintln!("CHAIN BROKEN: {e}");
                    bail!("audit log integrity failure");
                }
            }
            return Ok(());
        }
        _ => {}
    }

    // Everything below joins the network.
    let (topic, bootstrap) = match &args.invite {
        Some(raw) => {
            let invite = Invite::decode(raw).context("decoding invite")?;
            (invite.topic, vec![invite.node_id()])
        }
        None => (fresh_topic(), vec![]),
    };

    let mut session = Session::start(
        args.data_dir.clone(),
        "operator",
        "Operator",
        topic,
        bootstrap,
    )
    .await
    .context("operator node")?;

    // Mesh with the inviter + pin our own admin key so our feed accepts
    // the records we sign.
    if let Some(raw) = &args.invite {
        let invite = Invite::decode(raw)?;
        let id = invite.node_id();
        session.add_peer_addr(invite.addr);
        session.join_gossip_peer(id).await?;
    }
    pin_admin_key(&args.data_dir, &admin.admin_pub())?;
    session.feed.admin_keys.insert(admin.admin_pub());

    match &args.command {
        Command::Govern { action } => {
            let gov = match action {
                GovernAction::Suspend { root, reason } => GovernanceAction::Suspend {
                    root: parse_root(root)?,
                    reason: reason.clone(),
                },
                GovernAction::Reinstate { root } => GovernanceAction::Reinstate {
                    root: parse_root(root)?,
                },
                GovernAction::Blocklist { hash, reason } => {
                    let bytes = data_encoding::HEXLOWER
                        .decode(hash.trim().as_bytes())
                        .context("bad hash hex")?;
                    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("hash must be 32 bytes"))?;
                    GovernanceAction::Blocklist {
                        hash: arr,
                        reason: reason.clone(),
                    }
                }
                GovernAction::BindHandle { handle, root } => GovernanceAction::BindHandle {
                    handle: handle.clone(),
                    root: parse_root(root)?,
                },
            };
            publish_governance(&mut session, &admin, gov).await?;
            // Pump long enough for the gossip mesh to form (n0 DNS discovery
            // takes seconds) and for the session's rebroadcast cycle to put
            // the record on the wire — a queued broadcast dies with the
            // endpoint when this process exits.
            for _ in 0..40 {
                session.pump().await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            println!("governance record signed and published.");
            println!("note: nodes enforce it on receipt; late joiners get it via rebroadcast.");
        }
        Command::Case {
            user_root,
            escrow_key,
            out,
            case_ref,
            sync_secs,
        } => {
            let user_root = parse_root(user_root)?;
            let escrow = parse_escrow_key(escrow_key)?;
            println!(
                "syncing records for {}s (waiting for the user's post log over gossip)…",
                sync_secs
            );
            let deadline = tokio::time::Instant::now() + Duration::from_secs(*sync_secs);
            while tokio::time::Instant::now() < deadline {
                session.pump().await;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            // Their serving-node address, for blob fetches.
            if let Some(entry) = session.feed.directory.get(&user_root) {
                for s in &entry.serving_nodes {
                    if let Ok(id) = iroh::EndpointId::from_str(s) {
                        session.join_gossip_peer(id).await?;
                    }
                }
            }

            let mut audit = AuditLog::open(args.data_dir.join("audit.jsonl"), admin.admin_pub())?;
            let n = run_case(&mut session, &escrow, &user_root, case_ref, out, &mut audit)?;
            println!("case {}: {} images decrypted to {}", case_ref, n, out.display());
            println!(
                "audit: {} entries, chain head:\n  {}",
                audit.entries().len(),
                data_encoding::HEXLOWER.encode(&audit.chain_head())
            );
            println!("(publish this hash periodically; it proves the log is unmodified)");
        }
        Command::Keygen | Command::Audit => unreachable!(),
    }

    Ok(())
}
