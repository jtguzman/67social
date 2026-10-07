//! Session: the application layer tying identity, feed, records, and the
//! Iroh node together. Shared verbatim by the headless node daemon and the
//! Tauri app shell — "one core, different front ends."

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use iroh::EndpointId;
use iroh_blobs::Hash as BlobHash;
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::crypto::{aead_open, aead_seal, SymKey};
use crate::feed::{Feed, FeedEvent};
use crate::keys::{EscrowIdentity, PubKey};
use crate::net::{Invite, Node, WireChatMessage};
use crate::records::{
    Audience, DevicePubLite, DirectoryEntry, Envelope, FollowRequest, Hash, MessageRequest,
    PostRecord, ReactionRecord, Record, RevocationRecord, Scale,
};
use crate::store::{DeviceStore, StoredIdentity};

/// AAD domains for the two encrypted payloads of a post.
pub const AAD_IMAGE: &[u8] = b"image";
pub const AAD_THUMB: &[u8] = b"thumb";

/// UI/session event stream, drained by the front end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionEvent {
    Feed(FeedEvent),
    ChatReceived { from: PubKey, body: String, sent_at: u64 },
    ChatUndeliverable { to: PubKey, body: String },
    JoinedTopic(String),
}

pub struct Session {
    pub store: DeviceStore,
    pub identity: StoredIdentity,
    pub node: Node,
    pub feed: Feed,
    /// The signed record log, in arrival order (persisted on change).
    pub records: Vec<Record>,
    /// Events pending pickup by the front end.
    pub events: Vec<SessionEvent>,
    /// Outbox: chat messages held while the peer is offline. Sender-held,
    /// delivered on reconnect — never touches a node.
    pub outbox: HashMap<PubKey, Vec<WireChatMessage>>,
    /// Last time we rebroadcast our own records (gossip has no history, so
    /// late-joining peers only learn our state via rebroadcast).
    last_rebroadcast: std::time::Instant,
}

impl Session {
    /// Load or create the identity, replay the record log, bring the Iroh
    /// node up on the topic.
    pub async fn start(
        data_dir: PathBuf,
        handle: &str,
        display_name: &str,
        topic: TopicId,
        bootstrap: Vec<EndpointId>,
    ) -> Result<Self> {
        let store = DeviceStore::new(&data_dir)?;
        let identity = store.load_or_create_identity(handle.to_string(), display_name.to_string())?;
        let device = identity.device()?;
        let root_pub = identity.root_pub()?;

        let stored = store.load_feed()?;
        let mut feed = Feed::new(Some(root_pub));
        let mut events = vec![];
        for rec in &stored.records {
            if let Ok(mut evs) = feed.apply(rec) {
                events.append(&mut evs);
            }
        }
        feed.audience_keys = stored.audience_keys.into_iter().collect();
        // First run: create the Followers audience key.
        feed.init_my_audience();
        feed.my_escrow = Some(identity.escrow()?);
        // Governance: pin admin keys (file created by the operator tool).
        feed.admin_keys = crate::admin::admin_keys_for(&data_dir);

        let node = Node::spawn(data_dir, identity.endpoint_secret(), topic, bootstrap).await?;

        let mut session = Self {
            store,
            identity,
            node,
            feed,
            records: stored.records,
            events: events.into_iter().map(SessionEvent::Feed).collect(),
            outbox: HashMap::new(),
            last_rebroadcast: std::time::Instant::now(),
        };
        session.publish_directory_entry(&device).await?;
        // Protect replayed posts' blobs before the first GC pass.
        session.update_keep_set();
        Ok(session)
    }

    pub fn invite(&self) -> Invite {
        Invite {
            topic: self.node.topic_id,
            addr: self.node.addr(),
        }
    }

    /// Publish the public-safe directory entry, signed by the root key.
    pub async fn publish_directory_entry(&mut self, device: &crate::keys::DeviceIdentity) -> Result<()> {
        let entry = DirectoryEntry {
            root: device.root,
            handle: self.identity.handle.clone(),
            display_name: self.identity.display_name.clone(),
            devices: vec![DevicePubLite {
                sign_pub: device.device_pub(),
                enc_pub: device.encrypt_pub(),
            }],
            escrow_pub: self.identity.escrow()?.public(),
            serving_nodes: vec![self.node.node_id().to_string()],
            updated_at: crate::now_ms(),
        };
        let env = entry.sign(&self.identity.root()?, device.encrypt_pub());
        self.apply_and_broadcast(Record::Directory(env)).await
    }

    /// Full posting pipeline: ingest guarantees → encrypt → blob store →
    /// signed record → gossip. The original image never leaves the device.
    pub async fn create_post(
        &mut self,
        image_bytes: &[u8],
        caption: &str,
        audience: Audience,
    ) -> Result<Hash> {
        let device = self.identity.device()?;
        // 1. Ingest: decode-validate, strip EXIF, normalize, thumbnail.
        let norm = crate::ingest::normalize_image(image_bytes)?;
        // 2. Per-post content key; encrypt image and thumbnail separately.
        let content_key = SymKey::generate();
        let image_ct = aead_seal(&content_key, &norm.image, AAD_IMAGE);
        let thumb_ct = aead_seal(&content_key, &norm.thumb, AAD_THUMB);
        // 3. Chunk + content-address via iroh-blobs (BLAKE3).
        let blob_hash = self.node.add_blob(&image_ct).await?;
        let thumb_hash = self.node.add_blob(&thumb_ct).await?;
        // 4. Signed post record with wrapped keys; gossip it.
        let escrow_pub = self.identity.escrow()?.public();
        let env = self.feed.build_post(
            &device,
            *blob_hash.as_bytes(),
            *thumb_hash.as_bytes(),
            caption,
            audience,
            &content_key,
            &escrow_pub,
            crate::now_ms(),
        )?;
        let id = env.payload.id;
        self.apply_and_broadcast(Record::Post(env)).await?;
        Ok(id)
    }

    /// Rate a post on one scale (1–5). Last-writer-wins per (rater, scale).
    pub async fn react(&mut self, post_id: &Hash, scale: Scale, value: u8) -> Result<()> {
        if !(1..=5).contains(&value) {
            return Err(anyhow!("reaction value must be 1–5"));
        }
        let device = self.identity.device()?;
        let entry = self
            .feed
            .posts
            .get(post_id)
            .ok_or_else(|| anyhow!("unknown post"))?
            .clone();
        let body = self
            .feed
            .seal_reaction(&entry.env.payload, scale, value, crate::now_ms());
        let rec = ReactionRecord {
            post_id: *post_id,
            rater: device.root,
            body,
        };
        let env = Envelope::sign_with_device(rec, &device);
        self.apply_and_broadcast(Record::Reaction(env)).await
    }

    /// Unlink (crypto-shredding): signed revocation + local key/chunk
    /// destruction. The network stops distributing the ciphertext; no one
    /// new can open it.
    pub async fn unlink(&mut self, post_id: &Hash) -> Result<()> {
        let device = self.identity.device()?;
        let entry = self
            .feed
            .posts
            .get(post_id)
            .ok_or_else(|| anyhow!("unknown post"))?
            .clone();
        let rev = RevocationRecord {
            author: device.root,
            post_id: *post_id,
            blob_hash: entry.env.payload.blob_hash,
            thumb_hash: entry.env.payload.thumb_hash,
            created_at: crate::now_ms(),
        };
        let env = Envelope::sign_with_device(rev, &device);
        self.apply_and_broadcast(Record::Revocation(env)).await?;
        Ok(())
    }

    // ---------- Social graph ----------

    pub async fn request_follow(&mut self, to: PubKey) -> Result<()> {
        let device = self.identity.device()?;
        let req = FollowRequest {
            from: device.root,
            to,
            created_at: crate::now_ms(),
        };
        let env = Envelope::sign_with_device(req, &device);
        self.apply_and_broadcast(Record::FollowRequest(env)).await
    }

    pub async fn accept_follow(&mut self, requester: &PubKey) -> Result<()> {
        let device = self.identity.device()?;
        let requester_enc = self
            .feed
            .pending_follow_requests
            .get(requester)
            .map(|env| env.enc_pub)
            .ok_or_else(|| anyhow!("no pending follow request from that user"))?;
        let env = self
            .feed
            .accept_follow(requester, &device, &requester_enc, crate::now_ms())?;
        self.apply_and_broadcast(Record::FollowDecision(env)).await
    }

    pub fn decline_follow(&mut self, requester: &PubKey) {
        self.feed.decline_follow(requester);
        self.persist();
    }

    pub async fn remove_follower(&mut self, follower: &PubKey) -> Result<()> {
        let device = self.identity.device()?;
        if self.feed.remove_follower(follower).is_some() {
            // Audience rotated: re-wrap old posts' content keys to the new
            // key and re-gossip. Images never move or re-encrypt.
            let rewrapped = self.feed.rewrap_posts_for_rotation(&device);
            for env in rewrapped {
                self.apply_and_broadcast(Record::Post(env)).await?;
            }
            self.persist();
        }
        Ok(())
    }

    pub async fn request_message(&mut self, to: PubKey) -> Result<()> {
        let device = self.identity.device()?;
        let req = MessageRequest {
            from: device.root,
            to,
            created_at: crate::now_ms(),
        };
        let env = Envelope::sign_with_device(req, &device);
        self.apply_and_broadcast(Record::MessageRequest(env)).await
    }

    pub async fn accept_message(&mut self, requester: &PubKey) -> Result<()> {
        let device = self.identity.device()?;
        let env = self.feed.accept_message(requester, &device, crate::now_ms());
        self.apply_and_broadcast(Record::MessageDecision(env)).await
    }

    pub fn decline_message(&mut self, requester: &PubKey) {
        self.feed.decline_message(requester);
        self.persist();
    }

    pub fn block_user(&mut self, user: &PubKey) {
        self.feed.block_user(user);
        self.persist();
    }

    pub fn end_chat(&mut self, peer: &PubKey) {
        self.feed.end_chat(peer);
        self.outbox.remove(peer);
        self.persist();
    }

    // ---------- Chat ----------

    /// Send a chat message over the direct stream. If the peer is offline,
    /// the message is held in the local outbox and delivered on reconnect —
    /// never stored on any node.
    pub async fn send_chat(&mut self, to: PubKey, body: &str) -> Result<()> {
        let device = self.identity.device()?;
        let msg = WireChatMessage {
            id: rand_id(),
            from_root: device.root.0,
            body: body.to_string(),
            sent_at: crate::now_ms(),
        };
        match self.endpoint_for(&to) {
            Some(endpoint) => match self.node.send_chat(endpoint, &msg).await {
                Ok(()) => Ok(()),
                Err(e) => {
                    self.outbox.entry(to).or_default().push(msg);
                    self.events.push(SessionEvent::ChatUndeliverable {
                        to,
                        body: body.to_string(),
                    });
                    Err(e)
                }
            },
            None => {
                self.outbox.entry(to).or_default().push(msg);
                Err(anyhow!("peer endpoint unknown; message held in outbox"))
            }
        }
    }

    /// Drain transport events: records from gossip, chat from direct
    /// streams; flush the chat outbox to peers that are now reachable.
    /// Call from the front end's tick loop.
    pub async fn pump(&mut self) {
        while let Ok(rec) = self.node.record_rx.try_recv() {
            if let Err(e) = self.apply_record(rec) {
                warn!("dropping record: {e}");
            }
        }
        while let Ok((_peer, msg)) = self.node.chat_rx.try_recv() {
            let from = PubKey(msg.from_root);
            // Only accept chat from users with an open chat gate.
            if self.feed.open_chats.contains(&from) {
                self.events.push(SessionEvent::ChatReceived {
                    from,
                    body: msg.body,
                    sent_at: msg.sent_at,
                });
            }
        }
        self.flush_outbox().await;

        // Gossip carries only live messages — no history. Rebroadast the
        // records we authored on an interval so late-joining peers (and
        // anyone who missed the live message) converge on our state.
        if self.last_rebroadcast.elapsed() > std::time::Duration::from_secs(5) {
            self.last_rebroadcast = std::time::Instant::now();
            self.rebroadcast_mine().await;
        }
    }

    /// Re-gossip every record this device authored. Gossip dedups on the
    /// wire; receivers dedupe by record equality in `apply_record`.
    async fn rebroadcast_mine(&self) {
        let Some(me) = self.feed.me else { return };
        let mine: Vec<Record> = self
            .records
            .iter()
            .filter(|rec| match rec {
                Record::Post(e) => e.payload.author == me,
                Record::Reaction(e) => e.payload.rater == me,
                Record::Revocation(e) => e.payload.author == me,
                Record::FollowRequest(e) => e.payload.from == me,
                Record::FollowDecision(e) => e.payload.author == me,
                Record::MessageRequest(e) => e.payload.from == me,
                Record::MessageDecision(e) => e.payload.author == me,
                Record::Directory(e) => e.payload.root == me,
                // Governance records relay through every node that holds
                // them (they are only in the log if this node applied one).
                Record::Governance(_) => true,
            })
            .cloned()
            .collect();
        for rec in mine {
            let _ = self.node.broadcast(&rec).await;
        }
    }

    /// Deliver held messages to any peer whose endpoint we now know and
    /// who is online. Outbox entries that still fail stay held.
    async fn flush_outbox(&mut self) {
        let peers: Vec<PubKey> = self.outbox.keys().copied().collect();
        for peer in peers {
            let Some(endpoint) = self.endpoint_for(&peer) else {
                continue;
            };
            let Some(msgs) = self.outbox.get(&peer) else {
                continue;
            };
            let mut remaining = Vec::new();
            let mut delivered_any = false;
            for msg in msgs.iter().cloned() {
                if delivered_any || self.node.send_chat(endpoint, &msg).await.is_ok() {
                    delivered_any = true;
                } else {
                    remaining.push(msg);
                }
            }
            if remaining.is_empty() {
                self.outbox.remove(&peer);
            } else {
                self.outbox.insert(peer, remaining);
            }
        }
    }

    /// Seed the address book with a peer's address (invite flow).
    pub fn add_peer_addr(&self, addr: iroh::EndpointAddr) {
        self.node.add_peer_addr(addr);
    }

    /// Ask gossip to mesh with this peer.
    pub async fn join_gossip_peer(&self, peer: EndpointId) -> Result<()> {
        self.node.join_gossip_peers(vec![peer]).await
    }

    /// Resolve a root key to a serving endpoint via the directory.
    pub fn endpoint_for(&self, root: &PubKey) -> Option<EndpointId> {
        self.feed.directory.get(root).and_then(|entry| {
            entry
                .serving_nodes
                .first()
                .and_then(|s| s.parse::<EndpointId>().ok())
        })
    }

    // ---------- Reading ----------

    /// The content key for a post, if we hold the right audience key.
    pub fn content_key_for(&self, post: &PostRecord) -> Option<SymKey> {
        self.feed.content_key_for(post)
    }

    /// Fetch + decrypt a blob (thumbnail or full image). Looks locally
    /// first, then fetches from the author's serving node — becoming a
    /// replica in the process.
    pub async fn decrypt_blob(&self, post: &PostRecord, which: BlobKind) -> Option<Vec<u8>> {
        let key = self.content_key_for(post)?;
        let (hash, aad) = match which {
            BlobKind::Image => (post.blob_hash, AAD_IMAGE),
            BlobKind::Thumb => (post.thumb_hash, AAD_THUMB),
        };
        let blob_hash = BlobHash::from(hash);
        let ct = match self.node.get_blob(&blob_hash).await {
            Ok(ct) => ct,
            Err(_) => {
                let endpoint = self.endpoint_for(&post.author)?;
                self.node.fetch_blob(endpoint, &blob_hash).await.ok()?
            }
        };
        aead_open(&key, &ct, aad).ok()
    }

    pub fn escrow_identity(&self) -> Result<EscrowIdentity> {
        self.identity.escrow().map_err(|e| anyhow!("{e}"))
    }

    // ---------- Internals ----------

    pub(crate) async fn apply_and_broadcast(&mut self, rec: Record) -> Result<()> {
        self.apply_record(rec.clone())?;
        // Gossip is best-effort: iroh queues messages until a peer joins.
        self.node.broadcast(&rec).await?;
        Ok(())
    }

    /// Verify + apply a record locally (no gossip). Used by tests and the
    /// operator tool; regular traffic arrives via `pump`.
    pub fn apply_record(&mut self, rec: Record) -> Result<()> {
        let events = self.feed.apply(&rec)?;
        let push_record = !events.is_empty();
        for ev in &events {
            // Open any sealed audience keys right away (we hold the device
            // key, the Feed does not).
            if matches!(ev, FeedEvent::AudienceKeySealed { .. }) {
                let device = self.identity.device()?;
                let opened = self.feed.open_pending_audience(&device);
                for author in opened {
                    self.events.push(SessionEvent::Feed(FeedEvent::FollowAccepted { from: author }));
                }
            }
        }
        // Idempotent duplicates produce no events; skip logging them. Also
        // dedupe exact copies (rebroadcasts arrive repeatedly).
        if push_record && !self.records.contains(&rec) {
            self.records.push(rec);
        }
        self.events.extend(events.into_iter().map(SessionEvent::Feed));
        self.update_keep_set();
        // Crypto-shredding: drop the GC-protection tags of any post that
        // is now unlinked; the next GC pass sweeps its chunks.
        let to_drop: Vec<iroh_blobs::Hash> = self
            .feed
            .posts
            .values()
            .filter(|p| p.unlinked)
            .flat_map(|p| {
                let post = &p.env.payload;
                [post.blob_hash, post.thumb_hash]
            })
            .map(iroh_blobs::Hash::from)
            .collect();
        if !to_drop.is_empty() {
            self.node.drop_keep_tags(to_drop);
        }
        self.persist();
        Ok(())
    }

    /// Sync the GC keep set with the feed: every blob + thumbnail hash of
    /// every post that is not unlinked. Unlinked hashes leave the set, so
    /// the next GC pass drops those chunks (crypto-shredding enforcement).
    pub fn update_keep_set(&self) {
        let hashes = self
            .feed
            .posts
            .values()
            .filter(|p| !p.unlinked)
            .flat_map(|p| {
                let post = &p.env.payload;
                [post.blob_hash, post.thumb_hash]
            })
            .map(iroh_blobs::Hash::from);
        self.node.keep.replace(hashes);
    }

    pub fn persist(&self) {
        if let Err(e) = self.store.persist(&self.records, &self.feed) {
            warn!("persist failed: {e}");
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BlobKind {
    Image,
    Thumb,
}

fn rand_id() -> [u8; 32] {
    use rand::RngCore;
    let mut id = [0u8; 32];
    rand::rng().fill_bytes(&mut id);
    id
}

/// A fresh random topic id (for the first node of a network).
pub fn fresh_topic() -> TopicId {
    TopicId::from(rand_id())
}
