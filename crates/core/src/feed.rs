//! Feed state: the verified record log and everything derived from it.
//!
//! Pure logic — no networking. Every record arrives as a signed
//! [`Record`]; `apply` verifies signatures and enrollment rules and
//! returns [`FeedEvent`]s for the UI. Last-writer-wins (by timestamp) per
//! (rater, scale) for reactions; revocations mark posts unlinked.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{aead_open, SymKey};
use crate::post_id;
use crate::keys::{DeviceIdentity, EscrowIdentity, PubKey};
use crate::records::{
    Audience, Caption, DirectoryEntry, Envelope, FollowDecision, FollowRequest, Hash,
    KeyMaterial, MessageDecision, MessageRequest, PostRecord, ReactionBody, ReactionRecord,
    Record, RevocationRecord, RootId, Scale,
};

/// My own audience ("Followers" circle) key with a rotation version.
#[derive(Debug, Clone)]
pub struct AudienceState {
    pub key: SymKey,
    pub version: u32,
}

/// A stored post with bookkeeping.
#[derive(Debug, Clone)]
pub struct PostEntry {
    pub env: Envelope<PostRecord>,
    /// True when we successfully fetched and decrypted the image.
    pub fetched: bool,
    /// True when the author (or an admin blocklist) unlinked it.
    pub unlinked: bool,
}

#[derive(Debug, Clone)]
pub struct ReactionEntry {
    pub rater: RootId,
    pub scale: Scale,
    pub value: u8,
    pub created_at: u64,
}

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("author is suspended")]
    AuthorSuspended,
    #[error("content is blocklisted")]
    ContentBlocklisted,
    #[error("record references unknown or self")]
    BadParticipants,
    #[error("post {0:?} not found")]
    UnknownPost(Hash),
    #[error("revocation not signed by the post author")]
    NotAuthor,
    #[error("user is blocked")]
    Blocked,
    #[error("record already applied")]
    Duplicate,
}

/// Events emitted to the UI when records are applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedEvent {
    PostAdded { post_id: Hash },
    PostUnlinked { post_id: Hash },
    ReactionUpdated { post_id: Hash },
    FollowRequest { from: RootId },
    FollowAccepted { from: RootId },
    FollowDeclined { from: RootId },
    /// A follow acceptance carried a sealed audience key; parked until the
    /// app layer opens it with the device encryption key
    /// (`open_pending_audience`).
    AudienceKeySealed { from: RootId },
    MessageRequest { from: RootId },
    MessageAccepted { from: RootId },
    MessageDeclined { from: RootId },
    DirectoryUpdated { root: RootId },
    GovernanceApplied,
}

#[derive(Debug, Default)]
pub struct Feed {
    /// Root key of the local user, if the feed is attached to an identity.
    pub me: Option<RootId>,
    pub posts: HashMap<Hash, PostEntry>,
    /// (post, rater, scale) → latest reaction, last-writer-wins.
    reactions: HashMap<Hash, HashMap<(RootId, Scale), ReactionEntry>>,
    pub revoked: HashSet<Hash>,
    pub directory: HashMap<RootId, DirectoryEntry>,
    /// Admin keys trusted for governance records.
    pub admin_keys: HashSet<PubKey>,
    /// Suspended roots.
    suspended: HashSet<RootId>,
    /// Blocklisted content hashes.
    blocklist: HashSet<Hash>,
    /// Pending follow requests addressed to me.
    pub pending_follow_requests: HashMap<RootId, Envelope<FollowRequest>>,
    /// Pending message requests addressed to me.
    pub pending_message_requests: HashMap<RootId, Envelope<MessageRequest>>,
    /// Roots whose follow request I accepted (my followers).
    pub my_followers: HashSet<RootId>,
    /// Roots I follow (whose audience keys I hold).
    pub following: HashSet<RootId>,
    /// Audience keys of other authors, received on follow acceptance.
    pub audience_keys: HashMap<RootId, SymKey>,
    /// My own audience state.
    pub my_audience: Option<AudienceState>,
    /// My escrow private key (held sealed on-device for the demo; in
    /// production this lives with the custody mediator until a case).
    pub my_escrow: Option<EscrowIdentity>,
    /// Escrow public keys of every directory user (for wrapping).
    pub escrow_pubs: HashMap<RootId, crate::crypto::EncryptPub>,
    /// Blocked users: cannot follow or message me.
    pub blocked: HashSet<RootId>,
    /// Users I have blocked.
    pub blocking: HashSet<RootId>,
    /// Message chats I accepted.
    pub open_chats: HashSet<RootId>,
    /// Audience keys that arrived sealed, awaiting the device encryption
    /// key to open (`open_pending_audience`).
    pending_seals: Option<HashMap<RootId, crate::records::SealedKey>>,
}

impl Feed {
    pub fn new(me: Option<RootId>) -> Self {
        Self {
            me,
            ..Default::default()
        }
    }

    /// Verify + apply a record. Returns events for the UI.
    pub fn apply(&mut self, record: &Record) -> Result<Vec<FeedEvent>, ApplyError> {
        match record {
            Record::Post(env) => self.apply_post(env),
            Record::Reaction(env) => self.apply_reaction(env),
            Record::Revocation(env) => self.apply_revocation(env),
            Record::FollowRequest(env) => self.apply_follow_request(env),
            Record::FollowDecision(env) => self.apply_follow_decision(env),
            Record::MessageRequest(env) => self.apply_message_request(env),
            Record::MessageDecision(env) => self.apply_message_decision(env),
            Record::Directory(env) => self.apply_directory(env),
            Record::Governance(env) => self.apply_governance(env),
        }
    }

    fn enforce_not_suspended(&self, root: &RootId) -> Result<(), ApplyError> {
        if self.suspended.contains(root) {
            return Err(ApplyError::AuthorSuspended);
        }
        if self.blocking.contains(root) {
            return Err(ApplyError::Blocked);
        }
        Ok(())
    }

    /// Is this account suspended by governance?
    pub fn is_suspended(&self, root: &RootId) -> bool {
        self.suspended.contains(root)
    }

    fn apply_post(&mut self, env: &Envelope<PostRecord>) -> Result<Vec<FeedEvent>, ApplyError> {
        let post = &env.payload;
        env.verify(&post.author).map_err(|_| ApplyError::BadSignature)?;
        self.enforce_not_suspended(&post.author)?;
        if self.blocklist.contains(&post.blob_hash) || self.blocklist.contains(&post.thumb_hash) {
            return Err(ApplyError::ContentBlocklisted);
        }
        if let Some(existing) = self.posts.get_mut(&post.id) {
            // Idempotent for exact duplicates — but a re-wrap after audience
            // rotation carries the same post id with new wrapped keys.
            // Replace the stored record so followers holding the rotated key
            // can open old posts again. The image never moved.
            if existing.env.payload.key_material != post.key_material {
                let unlinked = existing.unlinked;
                let fetched = existing.fetched;
                existing.env = env.clone();
                existing.unlinked = unlinked;
                existing.fetched = fetched;
                return Ok(vec![FeedEvent::PostAdded { post_id: post.id }]);
            }
            return Ok(vec![]);
        }
        self.posts.insert(
            post.id,
            PostEntry {
                env: env.clone(),
                fetched: false,
                unlinked: false,
            },
        );
        Ok(vec![FeedEvent::PostAdded { post_id: post.id }])
    }

    fn apply_reaction(&mut self, env: &Envelope<ReactionRecord>) -> Result<Vec<FeedEvent>, ApplyError> {
        let reaction = &env.payload;
        env.verify(&reaction.rater).map_err(|_| ApplyError::BadSignature)?;
        let post = self
            .posts
            .get(&reaction.post_id)
            .ok_or(ApplyError::UnknownPost(reaction.post_id))?;
        let author = post.env.payload.author;
        self.enforce_not_suspended(&reaction.rater)?;

        // Open the body if sealed (private post): needs the author's audience key.
        let opened = match &reaction.body {
            ReactionBody::Plain { scale, value, created_at } => ReactionEntry {
                rater: reaction.rater,
                scale: *scale,
                value: *value,
                created_at: *created_at,
            },
            ReactionBody::Sealed { .. } => {
                let key = self
                    .audience_keys
                    .get(&author)
                    .or(self.my_audience.as_ref().map(|a| &a.key))
                    .ok_or(ApplyError::BadSignature)?;
                match reaction.body.open_sealed(key) {
                    Some(ReactionBody::Plain { scale, value, created_at }) => ReactionEntry {
                        rater: reaction.rater,
                        scale,
                        value,
                        created_at,
                    },
                    _ => return Err(ApplyError::BadSignature),
                }
            }
        };

        // Last-writer-wins per (rater, scale).
        let by_scale = self.reactions.entry(reaction.post_id).or_default();
        let key = (reaction.rater, opened.scale);
        let newer = by_scale
            .get(&key)
            .map(|old| opened.created_at >= old.created_at)
            .unwrap_or(true);
        if newer {
            by_scale.insert(key, opened);
        }
        Ok(vec![FeedEvent::ReactionUpdated { post_id: reaction.post_id }])
    }

    fn apply_revocation(&mut self, env: &Envelope<RevocationRecord>) -> Result<Vec<FeedEvent>, ApplyError> {
        let rev = &env.payload;
        let post = self
            .posts
            .get(&rev.post_id)
            .ok_or(ApplyError::UnknownPost(rev.post_id))?
            .clone();
        // Only the post's author may unlink it: the revocation must name
        // the author and verify against their root key.
        if rev.author != post.env.payload.author {
            return Err(ApplyError::NotAuthor);
        }
        env.verify(&rev.author).map_err(|_| ApplyError::NotAuthor)?;
        self.revoked.insert(rev.post_id);
        if let Some(p) = self.posts.get_mut(&rev.post_id) {
            p.unlinked = true;
        }
        Ok(vec![FeedEvent::PostUnlinked { post_id: rev.post_id }])
    }

    fn apply_follow_request(&mut self, env: &Envelope<FollowRequest>) -> Result<Vec<FeedEvent>, ApplyError> {
        let req = &env.payload;
        env.verify(&req.from).map_err(|_| ApplyError::BadSignature)?;
        self.enforce_not_suspended(&req.from)?;
        if self.blocked.contains(&req.from) || self.blocking.contains(&req.from) {
            return Err(ApplyError::Blocked);
        }
        if self.my_followers.contains(&req.from) {
            return Ok(vec![]); // already a follower; request is stale
        }
        self.pending_follow_requests.insert(req.from, env.clone());
        Ok(vec![FeedEvent::FollowRequest { from: req.from }])
    }

    fn apply_follow_decision(&mut self, env: &Envelope<FollowDecision>) -> Result<Vec<FeedEvent>, ApplyError> {
        let dec = &env.payload;
        // Signed by the author's device; verify against the author root.
        env.verify(&dec.author).map_err(|_| ApplyError::BadSignature)?;
        self.enforce_not_suspended(&dec.author)?;
        if Some(dec.to) != self.me {
            return Ok(vec![]); // not addressed to me
        }
        let author = dec.author;
        if dec.accepted {
            if let Some(sealed) = &dec.audience_delivery {
                // Parked: opening needs my device encryption private key,
                // which the Feed does not hold. The app layer calls
                // `open_pending_audience` right after applying.
                self.pending_seals
                    .get_or_insert_with(Default::default)
                    .insert(author, sealed.clone());
                return Ok(vec![FeedEvent::AudienceKeySealed { from: author }]);
            }
            self.following.insert(author);
            Ok(vec![FeedEvent::FollowAccepted { from: author }])
        } else {
            Ok(vec![FeedEvent::FollowDeclined { from: author }])
        }
    }

    fn apply_message_request(&mut self, env: &Envelope<MessageRequest>) -> Result<Vec<FeedEvent>, ApplyError> {
        let req = &env.payload;
        env.verify(&req.from).map_err(|_| ApplyError::BadSignature)?;
        self.enforce_not_suspended(&req.from)?;
        if self.blocked.contains(&req.from) || self.blocking.contains(&req.from) {
            return Err(ApplyError::Blocked);
        }
        if self.open_chats.contains(&req.from) {
            return Ok(vec![]);
        }
        self.pending_message_requests.insert(req.from, env.clone());
        Ok(vec![FeedEvent::MessageRequest { from: req.from }])
    }

    fn apply_message_decision(&mut self, env: &Envelope<MessageDecision>) -> Result<Vec<FeedEvent>, ApplyError> {
        let dec = &env.payload;
        env.verify(&dec.author).map_err(|_| ApplyError::BadSignature)?;
        if Some(dec.to) != self.me {
            return Ok(vec![]);
        }
        if dec.accepted {
            self.open_chats.insert(dec.author);
            Ok(vec![FeedEvent::MessageAccepted { from: dec.author }])
        } else {
            Ok(vec![FeedEvent::MessageDeclined { from: dec.author }])
        }
    }

    fn apply_directory(&mut self, env: &Envelope<DirectoryEntry>) -> Result<Vec<FeedEvent>, ApplyError> {
        let entry = &env.payload;
        env.verify(&entry.root).map_err(|_| ApplyError::BadSignature)?;
        let root = entry.root;
        let newer = self
            .directory
            .get(&root)
            .map(|old| entry.updated_at >= old.updated_at)
            .unwrap_or(true);
        if newer {
            self.escrow_pubs.insert(root, entry.escrow_pub);
            self.directory.insert(root, entry.clone());
            return Ok(vec![FeedEvent::DirectoryUpdated { root }]);
        }
        Ok(vec![])
    }

    fn apply_governance(&mut self, env: &Envelope<crate::records::GovernanceRecord>) -> Result<Vec<FeedEvent>, ApplyError> {
        let gov = &env.payload;
        env.verify(&gov.admin).map_err(|_| ApplyError::BadSignature)?;
        if !self.admin_keys.contains(&gov.admin) {
            return Err(ApplyError::BadSignature);
        }
        match &gov.action {
            crate::records::GovernanceAction::Suspend { root, .. } => {
                self.suspended.insert(*root);
            }
            crate::records::GovernanceAction::Reinstate { root } => {
                self.suspended.remove(root);
            }
            crate::records::GovernanceAction::Blocklist { hash, .. } => {
                self.blocklist.insert(*hash);
                let to_unlink: Vec<Hash> = self
                    .posts
                    .values()
                    .filter(|p| {
                        p.env.payload.blob_hash == *hash || p.env.payload.thumb_hash == *hash
                    })
                    .map(|p| p.env.payload.id)
                    .collect();
                for id in to_unlink {
                    if let Some(p) = self.posts.get_mut(&id) {
                        p.unlinked = true;
                    }
                    self.revoked.insert(id);
                }
            }
            crate::records::GovernanceAction::BindHandle { handle, root } => {
                if let Some(entry) = self.directory.get_mut(root) {
                    entry.handle = handle.clone();
                }
            }
        }
        Ok(vec![FeedEvent::GovernanceApplied])
    }

    // ---------- Publishing (author side) ----------

    /// Build a signed post record from already-stored ciphertext.
    ///
    /// `content_key` encrypts image + thumb + (private) caption; it is
    /// wrapped to the audience (unless public) and to the escrow key.
    pub fn build_post(
        &self,
        device: &DeviceIdentity,
        blob_hash: Hash,
        thumb_hash: Hash,
        caption: &str,
        audience: Audience,
        content_key: &SymKey,
        escrow_pub: &crate::crypto::EncryptPub,
        created_at: u64,
    ) -> Result<Envelope<PostRecord>, ApplyError> {
        let id = post_id(&blob_hash, &thumb_hash);
        let key_material = match &audience {
            Audience::Public => KeyMaterial::Plain(content_key.clone()),
            Audience::Followers { .. } => {
                let audience_key = self
                    .my_audience
                    .as_ref()
                    .map(|a| &a.key)
                    .ok_or(ApplyError::BadSignature)?;
                KeyMaterial::Audience(crate::records::WrappedKey::wrap(audience_key, content_key))
            }
        };
        let caption_rec = match &audience {
            Audience::Public => Caption::Plain(caption.to_string()),
            // The caption is encrypted alongside the image — as protected
            // as the photo it describes.
            Audience::Followers { .. } => Caption::Sealed(crate::records::WrappedKey {
                wrapped: crate::crypto::aead_seal(content_key, caption.as_bytes(), b"caption"),
            }),
        };
        let record = PostRecord {
            id,
            author: device.root,
            blob_hash,
            thumb_hash,
            caption: caption_rec,
            audience,
            key_material,
            wrapped_escrow: crate::records::SealedKey::seal(escrow_pub, content_key)
                .map_err(|_| ApplyError::BadSignature)?,
            created_at,
        };
        Ok(Envelope::sign_with_device(record, device))
    }

    /// Re-wrap the content keys of my existing posts to the current
    /// audience key (used after rotation). Images never move or re-encrypt.
    pub fn rewrap_posts_for_rotation(&self, device: &DeviceIdentity) -> Vec<Envelope<PostRecord>> {
        let Some(aud) = &self.my_audience else {
            return vec![];
        };
        let Some(me) = self.me else {
            return vec![];
        };
        self.posts
            .values()
            .filter(|p| p.env.payload.author == me && !p.unlinked)
            .filter_map(|p| {
                let rec = &p.env.payload;
                // Recover the content key from the escrow seal — the author
                // device keeps its own copy of content keys in practice;
                // here we re-wrap from the escrow-sealed copy.
                if let Some(esc) = &self.my_escrow {
                    if let Ok(content) = rec.wrapped_escrow.open(&esc.private) {
                        let mut new_rec = rec.clone();
                        new_rec.key_material =
                            KeyMaterial::Audience(crate::records::WrappedKey::wrap(&aud.key, &content));
                        return Some(Envelope::sign_with_device(new_rec, device));
                    }
                }
                None
            })
            .collect()
    }

    // ---------- Reading ----------

    /// Unwrap a post's content key using available keys (audience key of
    /// the author, my own audience, or the escrow identity).
    pub fn content_key_for(&self, post: &PostRecord) -> Option<SymKey> {
        match &post.key_material {
            KeyMaterial::Plain(k) => Some(k.clone()),
            KeyMaterial::Audience(wrapped) => {
                // I am the author: use my audience key.
                if Some(post.author) == self.me {
                    if let Some(aud) = &self.my_audience {
                        if let Ok(k) = wrapped.unwrap(&aud.key) {
                            return Some(k);
                        }
                    }
                }
                // I follow the author: use the delivered audience key.
                if let Some(key) = self.audience_keys.get(&post.author) {
                    if let Ok(k) = wrapped.unwrap(key) {
                        return Some(k);
                    }
                }
                None
            }
        }
    }

    /// Escrow path: unwrap a content key with the escrow private key
    /// (case-based read, scoped to one user).
    pub fn escrow_key_for(&self, post: &PostRecord, escrow: &EscrowIdentity) -> Option<SymKey> {
        post.wrapped_escrow.open(&escrow.private).ok()
    }

    /// Decrypt a caption with a content key.
    pub fn open_caption(post: &PostRecord, content_key: &SymKey) -> Option<String> {
        match &post.caption {
            Caption::Plain(s) => Some(s.clone()),
            Caption::Sealed(w) => aead_open(content_key, &w.wrapped, b"caption")
                .ok()
                .and_then(|b| String::from_utf8(b).ok()),
        }
    }

    /// Aggregate reactions for a post: average and count per scale,
    /// last-writer-wins per (rater, scale). "4.2★ from 31, 4.8❤ from 27".
    pub fn aggregate(&self, post_id: &Hash) -> Vec<(Scale, f64, u32)> {
        let by_scale = match self.reactions.get(post_id) {
            Some(m) => m,
            None => return vec![],
        };
        let mut totals: HashMap<Scale, (u64, u32)> = HashMap::new();
        for r in by_scale.values() {
            let e = totals.entry(r.scale).or_insert((0, 0));
            e.0 += r.value as u64;
            e.1 += 1;
        }
        let mut out: Vec<(Scale, f64, u32)> = totals
            .into_iter()
            .map(|(scale, (sum, count))| (scale, sum as f64 / count as f64, count))
            .collect();
        out.sort_by_key(|(s, _, _)| *s as u8);
        out
    }

    /// My own rating for a post/scale, if any.
    pub fn my_reaction(&self, post_id: &Hash, rater: &RootId, scale: Scale) -> Option<u8> {
        self.reactions
            .get(post_id)
            .and_then(|m| m.get(&(*rater, scale)))
            .map(|r| r.value)
    }

    /// All reactions for a post (opened entries).
    pub fn reactions_of(&self, post_id: &Hash) -> Vec<ReactionEntry> {
        self.reactions
            .get(post_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Encrypt a reaction body for the post's audience. Ratings inherit
    /// the post's audience: private posts hide who rated what from
    /// non-members.
    pub fn seal_reaction(&self, post: &PostRecord, scale: Scale, value: u8, created_at: u64) -> ReactionBody {
        match &post.audience {
            crate::records::Audience::Public => ReactionBody::Plain { scale, value, created_at },
            Audience::Followers { author } => {
                // Members hold the author's audience key.
                if let Some(key) = self.audience_keys.get(author).or(self
                    .my_audience
                    .as_ref()
                    .filter(|_| Some(*author) == self.me)
                    .map(|a| &a.key))
                {
                    ReactionBody::seal_plain(key, scale, value, created_at)
                } else {
                    ReactionBody::Plain { scale, value, created_at }
                }
            }
        }
    }

    // ---------- Audience management ----------

    /// Initialize my Followers audience (once, at account creation).
    pub fn init_my_audience(&mut self) -> SymKey {
        if let Some(a) = &self.my_audience {
            return a.key.clone();
        }
        let key = SymKey::generate();
        self.my_audience = Some(AudienceState { key: key.clone(), version: 1 });
        key
    }

    /// Rotate the audience key (e.g. after removing a follower). New posts
    /// use the new key; old posts' wrapped keys get re-wrapped and
    /// re-gossiped — the images never move or re-encrypt.
    pub fn rotate_audience(&mut self) -> SymKey {
        let key = SymKey::generate();
        let version = self.my_audience.as_ref().map(|a| a.version + 1).unwrap_or(1);
        self.my_audience = Some(AudienceState { key: key.clone(), version });
        key
    }

    /// Remove a follower and rotate the audience key. New posts use the new
    /// key; old posts' wrapped keys get re-wrapped and re-gossiped. (A
    /// removed follower who cached the old key keeps access to ciphertext
    /// they already pulled — the documented cached-key gap.)
    pub fn remove_follower(&mut self, follower: &RootId) -> Option<SymKey> {
        if self.my_followers.remove(follower) {
            Some(self.rotate_audience())
        } else {
            None
        }
    }

    /// Accept a follow request: deliver the current audience key sealed to
    /// the new follower's public encryption key.
    pub fn accept_follow(
        &mut self,
        requester: &RootId,
        device: &DeviceIdentity,
        requester_enc: &crate::crypto::EncryptPub,
        created_at: u64,
    ) -> Result<Envelope<FollowDecision>, ApplyError> {
        if !self.pending_follow_requests.contains_key(requester) {
            return Err(ApplyError::BadParticipants);
        }
        self.pending_follow_requests.remove(requester);
        self.my_followers.insert(*requester);
        let audience = self.my_audience.as_ref().ok_or(ApplyError::BadSignature)?;
        let delivery = crate::records::SealedKey::seal(requester_enc, &audience.key)
            .map_err(|_| ApplyError::BadSignature)?;
        let dec = FollowDecision {
            author: device.root,
            to: *requester,
            accepted: true,
            audience_delivery: Some(delivery),
            audience_version: audience.version,
            created_at,
        };
        Ok(Envelope::sign_with_device(dec, device))
    }

    pub fn decline_follow(&mut self, requester: &RootId) {
        // Declining leaves no durable record.
        self.pending_follow_requests.remove(requester);
    }

    /// Accept a message request (opens an ephemeral chat).
    pub fn accept_message(
        &mut self,
        requester: &RootId,
        device: &DeviceIdentity,
        created_at: u64,
    ) -> Envelope<MessageDecision> {
        self.pending_message_requests.remove(requester);
        self.open_chats.insert(*requester);
        let dec = MessageDecision {
            author: device.root,
            to: *requester,
            accepted: true,
            created_at,
        };
        Envelope::sign_with_device(dec, device)
    }

    pub fn decline_message(&mut self, requester: &RootId) {
        self.pending_message_requests.remove(requester);
    }

    /// End a chat: signal the peer, then drop local state. The UI drops
    /// its localStorage copy.
    pub fn end_chat(&mut self, peer: &RootId) {
        self.open_chats.remove(peer);
    }

    pub fn block_user(&mut self, user: &RootId) {
        self.blocking.insert(*user);
        self.pending_follow_requests.remove(user);
        self.pending_message_requests.remove(user);
        self.end_chat(user);
        self.my_followers.remove(user);
    }
}

impl Feed {
    /// Open any parked, sealed audience keys with my device encryption key.
    /// Returns the authors whose keys were opened (they are now followed).
    pub fn open_pending_audience(&mut self, device: &DeviceIdentity) -> Vec<RootId> {
        let mut opened = vec![];
        if let Some(map) = self.pending_seals.as_mut() {
            let authors: Vec<RootId> = map.keys().copied().collect();
            for author in authors {
                let sealed = map.get(&author).unwrap();
                if let Ok(key) = sealed.open(&device.encrypt) {
                    self.audience_keys.insert(author, key);
                    self.following.insert(author);
                    map.remove(&author);
                    opened.push(author);
                }
            }
        }
        opened
    }
}

// Extra field added via a second impl block to keep the struct definition
// readable; Rust allows fields only in the definition, so this lives there.
// (pending_seals is declared in the struct above.)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DeviceIdentity, RootIdentity};
    use crate::records::{FollowRequest, MessageRequest, PostRecord, ReactionRecord, RevocationRecord};

    fn setup() -> (RootIdentity, DeviceIdentity, RootIdentity, DeviceIdentity) {
        let root_a = RootIdentity::generate();
        let dev_a = DeviceIdentity::new_for(&root_a);
        let root_b = RootIdentity::generate();
        let dev_b = DeviceIdentity::new_for(&root_b);
        (root_a, dev_a, root_b, dev_b)
    }

    fn test_post(
        author_dev: &DeviceIdentity,
        audience: Audience,
        content: &SymKey,
        escrow_pub: &crate::crypto::EncryptPub,
        audience_key: &SymKey,
    ) -> Envelope<PostRecord> {
        let mut feed = Feed::new(Some(author_dev.root));
        feed.my_audience = Some(AudienceState {
            key: audience_key.clone(),
            version: 1,
        });
        feed.build_post(
            author_dev,
            [1u8; 32],
            [2u8; 32],
            "hello",
            audience,
            content,
            escrow_pub,
            1000,
        )
        .unwrap()
    }

    #[test]
    fn post_lifecycle_public() {
        let (_root_a, dev_a, root_b, _dev_b) = setup();
        let esc = crate::keys::EscrowIdentity::generate();
        let content = SymKey::generate();
        let post = test_post(&dev_a, Audience::Public, &content, &esc.public(), &SymKey::generate());

        let mut feed = Feed::new(Some(root_b.root_pub()));
        let events = feed.apply(&Record::Post(post.clone())).unwrap();
        assert!(matches!(events[0], FeedEvent::PostAdded { .. }));

        // Public: content key is right there.
        let entry = feed.posts.get(&post.payload.id).unwrap();
        assert_eq!(feed.content_key_for(&entry.env.payload).unwrap(), content);
        assert_eq!(Feed::open_caption(&entry.env.payload, &content).unwrap(), "hello");
        assert!(feed.my_reaction(&post.payload.id, &root_b.root_pub(), Scale::Stars).is_none());
    }

    #[test]
    fn private_post_readable_by_follower_via_audience_key() {
        let (root_a, dev_a, root_b, dev_b) = setup();
        let esc = crate::keys::EscrowIdentity::generate();
        let content = SymKey::generate();
        // One audience key, shared by the post wrapping and the author's
        // audience state (the same key that gets delivered on accept).
        let audience_key = SymKey::generate();
        let post = test_post(&dev_a, Audience::Followers { author: root_a.root_pub() }, &content, &esc.public(), &audience_key);

        let mut feed_b = Feed::new(Some(root_b.root_pub()));
        feed_b.apply(&Record::Post(post.clone())).unwrap();
        // No audience key yet → unreadable.
        let entry = feed_b.posts.get(&post.payload.id).unwrap();
        assert!(feed_b.content_key_for(&entry.env.payload).is_none());

        // Author accepts B's follow request, delivering the audience key.
        let mut feed_a = Feed::new(Some(root_a.root_pub()));
        feed_a.my_audience = Some(AudienceState {
            key: audience_key,
            version: 1,
        });
        feed_a
            .apply(&Record::FollowRequest(Envelope::sign_with_device(
                FollowRequest { from: root_b.root_pub(), to: root_a.root_pub(), created_at: 1 },
                &dev_b,
            )))
            .unwrap();
        let decision = feed_a
            .accept_follow(&root_b.root_pub(), &dev_a, &dev_b.encrypt.public(), 2)
            .unwrap();

        // B applies the decision: the sealed key is parked until the app
        // layer opens it with the device encryption private key.
        let events = feed_b.apply(&Record::FollowDecision(decision.clone())).unwrap();
        assert!(matches!(events[0], FeedEvent::AudienceKeySealed { .. }));
        assert!(feed_b.pending_seals.as_ref().map(|m| !m.is_empty()).unwrap_or(false));
        let opened = feed_b.open_pending_audience(&dev_b);
        assert_eq!(opened, vec![root_a.root_pub()]);

        // Now the private post opens.
        let entry = feed_b.posts.get(&post.payload.id).unwrap();
        assert_eq!(feed_b.content_key_for(&entry.env.payload).unwrap(), content);
    }

    #[test]
    fn reactions_last_writer_wins_and_aggregate() {
        let (root_a, dev_a, _root_b, _dev_b) = setup();
        let esc = crate::keys::EscrowIdentity::generate();
        let post = test_post(&dev_a, Audience::Public, &SymKey::generate(), &esc.public(), &SymKey::generate());
        let mut feed = Feed::new(Some(root_a.root_pub()));
        feed.apply(&Record::Post(post.clone())).unwrap();

        let rate = |feed: &mut Feed, from: &DeviceIdentity, v: u8, ts: u64| {
            let rec = ReactionRecord {
                post_id: post.payload.id,
                rater: from.root,
                body: ReactionBody::Plain { scale: Scale::Stars, value: v, created_at: ts },
            };
            feed.apply(&Record::Reaction(Envelope::sign_with_device(rec, from))).unwrap();
        };

        let rater1 = DeviceIdentity::new_for(&RootIdentity::generate());
        let rater2 = DeviceIdentity::new_for(&RootIdentity::generate());
        // register raters' reactions
        rate(&mut feed, &rater1, 5, 10);
        rate(&mut feed, &rater2, 3, 11);
        rate(&mut feed, &rater1, 1, 12); // later timestamp wins

        let agg = feed.aggregate(&post.payload.id);
        assert_eq!(agg, vec![(Scale::Stars, 2.0, 2)]);
        assert_eq!(feed.my_reaction(&post.payload.id, &rater1.root, Scale::Stars), Some(1));
    }

    #[test]
    fn reaction_sealed_for_private_posts() {
        let (root_a, dev_a, root_b, dev_b) = setup();
        let esc = crate::keys::EscrowIdentity::generate();
        let audience_key = SymKey::generate();
        let content = SymKey::generate();
        let post = test_post(&dev_a, Audience::Followers { author: root_a.root_pub() }, &content, &esc.public(), &audience_key);

        let mut feed_b = Feed::new(Some(root_b.root_pub()));
        feed_b.apply(&Record::Post(post.clone())).unwrap();
        let entry = feed_b.posts.get(&post.payload.id).unwrap().clone();

        // A follower holds the author's audience key and seals reactions.
        feed_b.audience_keys.insert(root_a.root_pub(), audience_key.clone());
        let body = feed_b.seal_reaction(&entry.env.payload, Scale::Hearts, 4, 9);
        assert!(matches!(body, ReactionBody::Sealed { .. }));

        // The author's feed opens it with the same audience key.
        let mut feed_a = Feed::new(Some(root_a.root_pub()));
        feed_a.apply(&Record::Post(post.clone())).unwrap();
        feed_a.audience_keys.insert(root_a.root_pub(), audience_key);
        let rec = ReactionRecord { post_id: post.payload.id, rater: root_b.root_pub(), body };
        feed_a.apply(&Record::Reaction(Envelope::sign_with_device(rec, &dev_b))).unwrap();
        assert_eq!(feed_a.my_reaction(&post.payload.id, &root_b.root_pub(), Scale::Hearts), Some(4));
    }

    #[test]
    fn unlink_only_by_author_and_marks_unlinked() {
        let (root_a, dev_a, root_b, _dev_b) = setup();
        let esc = crate::keys::EscrowIdentity::generate();
        let post = test_post(&dev_a, Audience::Public, &SymKey::generate(), &esc.public(), &SymKey::generate());

        let mut feed = Feed::new(Some(root_b.root_pub()));
        feed.apply(&Record::Post(post.clone())).unwrap();

        // Signed by a non-author → rejected.
        let fake_rev = Envelope::sign_with_device(
            RevocationRecord { author: root_a.root_pub(), post_id: post.payload.id, blob_hash: post.payload.blob_hash, thumb_hash: post.payload.thumb_hash, created_at: 5 },
            &DeviceIdentity::new_for(&root_b),
        );
        assert!(feed.apply(&Record::Revocation(fake_rev)).is_err());

        // Signed by the author → post unlinked.
        let rev = Envelope::sign_with_device(
            RevocationRecord { author: root_a.root_pub(), post_id: post.payload.id, blob_hash: post.payload.blob_hash, thumb_hash: post.payload.thumb_hash, created_at: 5 },
            &dev_a,
        );
        feed.apply(&Record::Revocation(rev)).unwrap();
        assert!(feed.revoked.contains(&post.payload.id));
    }

    #[test]
    fn blocklist_governance_hides_posts() {
        let (root_a, dev_a, _root_b, _dev_b) = setup();
        let esc = crate::keys::EscrowIdentity::generate();
        let post = test_post(&dev_a, Audience::Public, &SymKey::generate(), &esc.public(), &SymKey::generate());

        let admin = crate::keys::PrivKey::generate();
        let mut feed = Feed::new(Some(root_a.root_pub()));
        feed.admin_keys.insert(admin.public());
        feed.apply(&Record::Post(post.clone())).unwrap();

        let gov = crate::records::GovernanceRecord {
            action: crate::records::GovernanceAction::Blocklist { hash: post.payload.blob_hash, reason: "test".into() },
            admin: admin.public(),
            created_at: 1,
        };
        feed.apply(&Record::Governance(Envelope::sign_with_device(gov, &DeviceIdentity::new_for(&root_a)))).unwrap_err(); // signed by wrong device

        // The governance record must be signed directly by the admin key;
        // our Envelope signs with a device key, so sign with the admin priv.
        let bytes = postcard::to_allocvec(&crate::records::GovernanceRecord {
            action: crate::records::GovernanceAction::Blocklist { hash: post.payload.blob_hash, reason: "test".into() },
            admin: admin.public(),
            created_at: 1,
        })
        .unwrap();
        let env = crate::records::Envelope {
            payload: crate::records::GovernanceRecord {
                action: crate::records::GovernanceAction::Blocklist { hash: post.payload.blob_hash, reason: "test".into() },
                admin: admin.public(),
                created_at: 1,
            },
            signer: admin.public(),
            enc_pub: esc.public(),
            cert: None,
            signature: crate::records::SigBytes(admin.sign(&bytes).to_vec()),
        };
        feed.apply(&Record::Governance(env)).unwrap();
        assert!(feed.posts.get(&post.payload.id).unwrap().unlinked);
    }

    #[test]
    fn message_request_gate() {
        let (root_a, dev_a, root_b, dev_b) = setup();
        let mut feed_a = Feed::new(Some(root_a.root_pub()));
        let req_env = Envelope::sign_with_device(
            MessageRequest { from: root_b.root_pub(), to: root_a.root_pub(), created_at: 1 },
            &dev_b,
        );
        feed_a.apply(&Record::MessageRequest(req_env)).unwrap();
        assert!(feed_a.pending_message_requests.contains_key(&root_b.root_pub()));

        let decision = feed_a.accept_message(&root_b.root_pub(), &dev_a, 2);
        let mut feed_b = Feed::new(Some(root_b.root_pub()));
        feed_b.apply(&Record::MessageDecision(decision)).unwrap();
        assert!(feed_b.open_chats.contains(&root_a.root_pub()));
    }

    #[test]
    fn rotation_rewraps_posts_and_excludes_removed_follower() {
        let (root_a, dev_a, root_b, _dev_b) = setup();
        let esc = EscrowIdentity::generate();
        let audience_v1 = SymKey::generate();
        let content = SymKey::generate();
        let post = test_post(
            &dev_a,
            Audience::Followers { author: root_a.root_pub() },
            &content,
            &esc.public(),
            &audience_v1,
        );

        // Follower B holds audience v1 and can open the post.
        let mut feed_b = Feed::new(Some(root_b.root_pub()));
        feed_b.apply(&Record::Post(post.clone())).unwrap();
        feed_b.audience_keys.insert(root_a.root_pub(), audience_v1.clone());
        let entry = feed_b.posts.get(&post.payload.id).unwrap();
        assert_eq!(feed_b.content_key_for(&entry.env.payload).unwrap(), content);

        // Author removes B → rotation → re-wrap old posts to the new key.
        let mut feed_a = Feed::new(Some(root_a.root_pub()));
        feed_a.me = Some(root_a.root_pub());
        feed_a.my_followers.insert(root_b.root_pub());
        feed_a.my_audience = Some(AudienceState { key: audience_v1.clone(), version: 1 });
        feed_a.my_escrow = Some(EscrowIdentity::generate());
        // The author's escrow must match the post's escrow seal to recover
        // content keys; rebuild the post under feed_a's escrow.
        let content2 = SymKey::generate();
        let post2 = feed_a
            .build_post(
                &dev_a,
                [9u8; 32],
                [8u8; 32],
                "old post",
                Audience::Followers { author: root_a.root_pub() },
                &content2,
                &feed_a.my_escrow.as_ref().unwrap().public(),
                500,
            )
            .unwrap();
        feed_a.apply(&Record::Post(post2)).unwrap();

        let audience_v2 = feed_a.remove_follower(&root_b.root_pub()).unwrap();
        assert_ne!(audience_v2, audience_v1);
        let rewrapped = feed_a.rewrap_posts_for_rotation(&dev_a);
        assert_eq!(rewrapped.len(), 1);

        // A remaining follower holding v2 applies the re-wrapped record and
        // opens the old post; B with only v1 cannot.
        let root_c = RootIdentity::generate();
        let mut feed_c = Feed::new(Some(root_c.root_pub()));
        feed_c.apply(&Record::Post(rewrapped[0].clone())).unwrap();
        feed_c.audience_keys.insert(root_a.root_pub(), audience_v2.clone());
        let entry_c = feed_c.posts.get(&rewrapped[0].payload.id).unwrap();
        assert_eq!(feed_c.content_key_for(&entry_c.env.payload).unwrap(), content2);

        let mut feed_b2 = Feed::new(Some(root_b.root_pub()));
        feed_b2.apply(&Record::Post(rewrapped[0].clone())).unwrap();
        feed_b2.audience_keys.insert(root_a.root_pub(), audience_v1);
        let entry_b2 = feed_b2.posts.get(&rewrapped[0].payload.id).unwrap();
        assert!(feed_b2.content_key_for(&entry_b2.env.payload).is_none());
    }

    #[test]
    fn escrow_read_scoped_to_one_user() {
        let (root_a, dev_a, _root_b, _dev_b) = setup();
        let esc = crate::keys::EscrowIdentity::generate();
        let content = SymKey::generate();
        let post = test_post(&dev_a, Audience::Followers { author: root_a.root_pub() }, &content, &esc.public(), &SymKey::generate());

        let mut feed = Feed::new(Some(root_a.root_pub()));
        feed.apply(&Record::Post(post.clone())).unwrap();
        let entry = feed.posts.get(&post.payload.id).unwrap();

        // The operator holding this user's escrow key can read.
        assert_eq!(feed.escrow_key_for(&entry.env.payload, &esc).unwrap(), content);
        // A different user's escrow key cannot.
        let other_esc = crate::keys::EscrowIdentity::generate();
        assert!(feed.escrow_key_for(&entry.env.payload, &other_esc).is_none());
        assert!(matches!(entry.env.payload.audience, Audience::Followers { .. }));
    }
}