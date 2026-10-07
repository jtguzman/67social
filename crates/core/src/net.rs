//! Iroh transport: one endpoint per device carrying all protocols.
//!
//! - **iroh-blobs**: content-addressed ciphertext storage and transfer.
//!   Chunks are BLAKE3-addressed; hashes reveal nothing about content.
//! - **iroh-gossip**: pub/sub of signed records to the network topic.
//! - **Direct chat**: a private ALPN protocol over an authenticated Iroh
//!   stream; end-to-end encrypted by QUIC. Nothing here writes chat to
//!   any store — persistence is the UI's `localStorage` only.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};
use futures::StreamExt;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::store::{GcConfig, ProtectOutcome};
use iroh_blobs::{BlobsProtocol, Hash};
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tracing::info;

use crate::records::Record;

/// ALPN for the ephemeral chat protocol.
pub const CHAT_ALPN: &[u8] = b"67social/chat/1";

/// Hard cap on one chat frame (defense against memory exhaustion).
const MAX_CHAT_FRAME: usize = 64 * 1024;

/// An invitation: the network topic plus our full endpoint address, so a
/// peer can dial us directly and join our gossip topic — no external
/// discovery needed. Shared out-of-band (QR / paste).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub topic: TopicId,
    pub addr: EndpointAddr,
}

impl Invite {
    pub fn node_id(&self) -> EndpointId {
        self.addr.id
    }
}

impl Invite {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("invite serialization");
        data_encoding::BASE64URL_NOPAD.encode(&json)
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(s.trim().as_bytes())
            .map_err(|e| anyhow!("bad invite base64: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("bad invite json: {e}"))
    }
}

/// An incoming chat message from the wire (never persisted here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireChatMessage {
    pub id: [u8; 32],
    pub from_root: [u8; 32],
    pub body: String,
    pub sent_at: u64,
}

/// The set of ciphertext blobs this device should keep: every blob and
/// thumbnail hash of non-unlinked posts it knows. GC sweeps everything
/// else — this is the crypto-shredding enforcement point on nodes: when a
/// revocation lands, the unlinked hashes leave the keep set and the next
/// pass drops the chunks.
#[derive(Debug, Clone, Default)]
pub struct KeepSet(Arc<Mutex<HashSet<Hash>>>);

impl KeepSet {
    pub fn replace(&self, hashes: impl IntoIterator<Item = Hash>) {
        let mut guard = self.0.lock().unwrap();
        *guard = hashes.into_iter().collect();
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.lock().unwrap().is_empty()
    }

    /// GC callback: protect exactly the hashes currently in the keep set.
    fn as_protect_cb(&self) -> iroh_blobs::store::ProtectCb {
        let keep = self.clone();
        Arc::new(move |live: &mut HashSet<Hash>| {
            let keep = keep.clone();
            Box::pin(async move {
                live.extend(keep.0.lock().unwrap().iter().copied());
                ProtectOutcome::Continue
            })
        })
    }
}

/// GC interval in seconds (env override; default 15).
fn gc_interval_secs() -> u64 {
    std::env::var("SOCIAL67_GC_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15)
}

/// Sets a stop flag when dropped, so background tasks holding store
/// references exit when the Node does — releasing the blob DB lock for
/// the next session on the same data dir.
struct StopFlag(Arc<std::sync::atomic::AtomicBool>);

impl Drop for StopFlag {
    fn drop(&mut self) {
        self.0
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Chat protocol handler: accepts an incoming connection and relays
/// messages to the app layer. No storage whatsoever.
#[derive(Debug, Clone)]
struct ChatHandler {
    tx: mpsc::UnboundedSender<(EndpointId, WireChatMessage)>,
}

impl ProtocolHandler for ChatHandler {
    async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        let peer = connection.remote_id();
        let (mut send, mut recv) = connection.accept_bi().await.map_err(AcceptError::from_err)?;
        let mut buf = Vec::new();
        loop {
            let byte = match recv.read_u8().await {
                Ok(b) => b,
                Err(_) => break,
            };
            if byte == b'\n' {
                if let Ok(msg) = serde_json::from_slice::<WireChatMessage>(&buf) {
                    let _ = self.tx.send((peer, msg));
                }
                buf.clear();
                // Acknowledge so the sender knows delivery happened while
                // both devices were online.
                if send.write_all(b"y\n").await.is_err() {
                    break;
                }
            } else {
                buf.push(byte);
                if buf.len() > MAX_CHAT_FRAME {
                    break;
                }
            }
        }
        Ok(())
    }
}

/// A running Iroh node: endpoint + blobs + gossip + chat.
pub struct Node {
    pub endpoint: Endpoint,
    pub router: Router,
    pub store: FsStore,
    pub gossip: Gossip,
    gossip_sender: iroh_gossip::api::GossipSender,
    /// The gossip topic id, for building invites.
    pub topic_id: TopicId,
    /// Verified-transport records arriving from peers (postcard-decoded).
    pub record_rx: mpsc::UnboundedReceiver<Record>,
    /// Chat messages arriving from peers.
    pub chat_rx: mpsc::UnboundedReceiver<(EndpointId, WireChatMessage)>,
    /// In-memory address book for peers learned out-of-band (invites,
    /// directory entries). Complements the n0 discovery services.
    addr_book: MemoryLookup,
    /// Hashes to protect from GC (recomputed by the session from the feed).
    pub keep: KeepSet,
    /// Send hashes here to drop their GC-protection tags (crypto-shredding).
    tag_drop_tx: mpsc::UnboundedSender<Hash>,
    /// Sets true on drop: background tasks check it and exit.
    _stop: StopFlag,
}

impl Node {
    /// Bind an endpoint (with a stable secret so the endpoint id survives
    /// restarts), mount blobs + gossip + chat on a router, and join the
    /// network topic. `bootstrap` peers are dialed to join the swarm.
    pub async fn spawn(
        data_dir: PathBuf,
        secret: [u8; 32],
        topic_id: TopicId,
        bootstrap: Vec<EndpointId>,
    ) -> Result<Self> {
        let secret_key = iroh::SecretKey::from_bytes(&secret);
        let addr_book = MemoryLookup::new();
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .address_lookup(addr_book.clone())
            .bind()
            .await
            .map_err(|e| anyhow!("binding iroh endpoint: {e}"))?;

        let keep = KeepSet::default();
        let blobs_root = data_dir.join("blobs");
        let mut store_opts = iroh_blobs::store::fs::options::Options::new(&blobs_root);
        store_opts.gc = Some(GcConfig {
            interval: n0_future::time::Duration::from_secs(gc_interval_secs()),
            add_protected: Some(keep.as_protect_cb()),
        });
        // Mirrors FsStore::load: db_path is the *database file* inside the
        // blobs root, not the root itself.
        let store = FsStore::load_with_opts(blobs_root.join("blobs.db"), store_opts)
            .await
            .map_err(|e| anyhow!("opening blob store: {e}"))?;

        let gossip = Gossip::builder().spawn(endpoint.clone());

        let (chat_tx, chat_rx) = mpsc::unbounded_channel();
        let chat_handler = ChatHandler { tx: chat_tx };

        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store, None))
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(CHAT_ALPN, chat_handler)
            .spawn();

        info!(node = %endpoint.id(), "iroh node up");

        // Join (or create) the gossip topic; bootstrap peers come from the
        // invite when joining someone else's network.
        let topic = gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|e| anyhow!("joining gossip topic: {e}"))?;
        let (gossip_sender, mut receiver) = topic.split();

        // Tag-drop task: crypto-shredding deletions, one at a time. Exits
        // when the Node (and its StopFlag) is dropped.
        let (tag_drop_tx, mut tag_drop_rx) = mpsc::unbounded_channel::<Hash>();
        let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let store = store.clone();
            let stop = Arc::clone(&stop_flag);
            tokio::spawn(async move {
                loop {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    match tag_drop_rx.try_recv() {
                        Ok(hash) => {
                            let _ = store.tags().delete(hash.to_string()).await;
                        }
                        Err(mpsc::error::TryRecvError::Empty) => {
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
            });
        }

        let (record_tx, record_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(item) = receiver.next().await {
                if let Ok(iroh_gossip::api::Event::Received(msg)) = item {
                    if let Ok(rec) = postcard::from_bytes::<Record>(&msg.content) {
                        let _ = record_tx.send(rec);
                    }
                }
            }
        });

        Ok(Self {
            endpoint,
            router,
            store,
            gossip,
            gossip_sender,
            topic_id,
            record_rx,
            chat_rx,
            addr_book,
            keep,
            tag_drop_tx,
            _stop: StopFlag(stop_flag),
        })
    }

    pub fn node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Our own address (endpoint id + socket addresses), for sharing with
    /// peers out-of-band.
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Seed the address book with a peer's address (from an invite or a
    /// directory entry).
    pub fn add_peer_addr(&self, addr: EndpointAddr) {
        self.addr_book.add_endpoint_info(addr);
    }

    /// Ask gossip to connect to these peers in our topic swarm.
    pub async fn join_gossip_peers(&self, peers: Vec<EndpointId>) -> Result<()> {
        self.gossip_sender
            .join_peers(peers)
            .await
            .map_err(|e| anyhow!("gossip join_peers: {e}"))
    }

    /// Publish a signed record to the gossip topic.
    pub async fn broadcast(&self, record: &Record) -> Result<()> {
        let bytes = postcard::to_allocvec(record)?;
        self.gossip_sender
            .broadcast(bytes.into())
            .await
            .map_err(|e| anyhow!("gossip broadcast: {e}"))?;
        Ok(())
    }

    /// Store ciphertext locally (the author's device seeds its own posts).
    ///
    /// The blob gets a named tag derived from its hash — the GC protection
    /// that keeps it until the post is unlinked (then the tag is dropped
    /// and the next pass sweeps the chunks).
    pub async fn add_blob(&self, bytes: &[u8]) -> Result<Hash> {
        let tt = self
            .store
            .blobs()
            .add_slice(bytes)
            .temp_tag()
            .await
            .map_err(|e| anyhow!("adding blob: {e}"))?;
        let hash = tt.hash();
        let haf = tt.hash_and_format();
        drop(tt);
        // Name the tag after the hash so unlink can find and drop it.
        self.store
            .tags()
            .set(hash.to_string(), haf)
            .await
            .map_err(|e| anyhow!("tagging blob: {e}"))?;
        Ok(hash)
    }

    /// Drop the GC-protection tags for these hashes: they become sweepable
    /// at the next pass (crypto-shredding). Deleting a missing tag is a
    /// no-op. Non-blocking; a dedicated task performs the deletions.
    pub fn drop_keep_tags(&self, hashes: impl IntoIterator<Item = Hash>) {
        for hash in hashes {
            let _ = self.tag_drop_tx.send(hash);
        }
    }

    pub async fn get_blob(&self, hash: &Hash) -> Result<Vec<u8>> {
        let bytes = self
            .store
            .blobs()
            .get_bytes(*hash)
            .await
            .map_err(|e| anyhow!("reading blob: {e}"))?;
        Ok(bytes.to_vec())
    }

    /// Fetch a blob from a remote node and keep it (replication: this
    /// device becomes another replica of the ciphertext).
    pub async fn fetch_blob(&self, from: EndpointId, hash: &Hash) -> Result<Vec<u8>> {
        let conn = self
            .endpoint
            .connect(from, iroh_blobs::ALPN)
            .await
            .map_err(|e| anyhow!("dialing blob provider: {e}"))?;
        self.store
            .remote()
            .fetch(conn, *hash)
            .complete()
            .await
            .map_err(|e| anyhow!("fetching blob: {e}"))?;
        self.get_blob(hash).await
    }

    /// Send a chat message over the direct, authenticated chat stream.
    /// Returns Ok only if the peer was online and acknowledged; otherwise
    /// the caller keeps the message in its outbox (sender-held, delivered
    /// on reconnect).
    pub async fn send_chat(&self, to: EndpointId, msg: &WireChatMessage) -> Result<()> {
        let conn = self
            .endpoint
            .connect(to, CHAT_ALPN)
            .await
            .map_err(|e| anyhow!("dialing peer for chat: {e}"))?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("opening chat stream: {e}"))?;
        let mut framed = serde_json::to_vec(msg)?;
        framed.push(b'\n');
        send.write_all(&framed).await?;
        let ack = recv.read_u8().await?;
        if ack != b'y' {
            bail!("chat message not acknowledged");
        }
        Ok(())
    }

    pub async fn shutdown(self) -> Result<()> {
        self.router
            .shutdown()
            .await
            .map_err(|e| anyhow!("router shutdown: {e}"))?;
        // Release the blob DB (redb lock) for the next session.
        self.store
            .shutdown()
            .await
            .map_err(|e| anyhow!("store shutdown: {e}"))?;
        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // The StopFlag (this) stops the tag-drop task; also signal the
        // store actor to shut down so the redb lock is released even when
        // the session is dropped without an explicit shutdown — e.g. when
        // a test block scope ends or an app instance closes.
        // Spawn inside Drop only works under a tokio runtime; Node is
        // always used from one.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let store = self.store.clone();
            handle.spawn(async move {
                let _ = store.shutdown().await;
            });
        }
        // Note: `_stop` (StopFlag) drops after this fn body.
    }
}

/// Map root keys (accounts) to endpoint ids — the directory's "serving
/// nodes" job. The MVP: a directory entry advertises the author's device
/// endpoint id.
#[derive(Debug, Default, Clone)]
pub struct ServingNodes(pub Arc<Mutex<HashMap<[u8; 32], EndpointId>>>);

impl ServingNodes {
    pub fn register(&self, root: [u8; 32], node: EndpointId) {
        self.0.lock().unwrap().insert(root, node);
    }

    pub fn lookup(&self, root: &[u8; 32]) -> Option<EndpointId> {
        self.0.lock().unwrap().get(root).copied()
    }
}

/// Public constructor for tests/examples: the KeepSet GC-protect callback.
pub fn keep_protect_cb(keep: &KeepSet) -> iroh_blobs::store::ProtectCb {
    keep.as_protect_cb()
}
