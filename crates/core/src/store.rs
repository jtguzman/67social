//! Local persistence: identity keys and feed state.
//!
//! This is *device-local* state only. Chat history deliberately lives
//! nowhere here — see the design document: the only chat persistence is
//! each device's own `localStorage`, handled by the UI layer.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{EncryptPriv, SymKey};
use crate::feed::Feed;
use crate::keys::{DeviceIdentity, EscrowIdentity, PrivKey, RootIdentity, PubKey};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid key material in stored identity")]
    BadKey,
}

/// Everything a device persists about its own identity.
#[derive(Serialize, Deserialize)]
pub struct StoredIdentity {
    /// Root signing key seed.
    pub root_sign: [u8; 32],
    /// Root encryption (X25519) private key.
    pub root_enc: [u8; 32],
    /// Device signing key seed.
    pub device_sign: [u8; 32],
    /// Device encryption private key.
    pub device_enc: [u8; 32],
    /// Root certification of the device key.
    pub device_cert: Vec<u8>,
    /// Escrow private key, held on-device for the MVP demo. In production
    /// this lives sealed with the custody mediator until a case opens.
    pub escrow: [u8; 32],
    /// Handle and display name.
    pub handle: String,
    pub display_name: String,
    /// The account's escrow public key, mirrored for convenience.
    pub created_at: u64,
}

impl StoredIdentity {
    pub fn create(handle: String, display_name: String) -> Self {
        let root = RootIdentity::generate();
        let device = DeviceIdentity::new_for(&root);
        let escrow = EscrowIdentity::generate();
        StoredIdentity {
            root_sign: root.key.to_bytes(),
            root_enc: root.encrypt.to_bytes(),
            device_sign: device.signing.to_bytes(),
            device_enc: device.encrypt.to_bytes(),
            device_cert: device.root_signature,
            escrow: escrow.to_bytes(),
            handle,
            display_name,
            created_at: crate::now_ms(),
        }
    }

    pub fn root(&self) -> Result<RootIdentity, StoreError> {
        Ok(RootIdentity {
            key: PrivKey::from_bytes(&self.root_sign).map_err(|_| StoreError::BadKey)?,
            encrypt: EncryptPriv::from_bytes(&self.root_enc).map_err(|_| StoreError::BadKey)?,
        })
    }

    pub fn device(&self) -> Result<DeviceIdentity, StoreError> {
        Ok(DeviceIdentity {
            signing: PrivKey::from_bytes(&self.device_sign).map_err(|_| StoreError::BadKey)?,
            encrypt: EncryptPriv::from_bytes(&self.device_enc).map_err(|_| StoreError::BadKey)?,
            root_signature: self.device_cert.clone(),
            root: self.root_pub()?,
        })
    }

    pub fn escrow(&self) -> Result<EscrowIdentity, StoreError> {
        EscrowIdentity::from_bytes(&self.escrow).map_err(|_| StoreError::BadKey)
    }

    pub fn root_pub(&self) -> Result<PubKey, StoreError> {
        // The root public key is derived from the stored root *signing*
        // seed — the seed is private key material, not the public key.
        Ok(PrivKey::from_bytes(&self.root_sign)
            .map_err(|_| StoreError::BadKey)?
            .public())
    }

    /// The device Iroh endpoint id: derived from the device signing key so
    /// the node id is stable across restarts.
    pub fn endpoint_secret(&self) -> [u8; 32] {
        self.device_sign
    }
}

/// Persisted feed snapshot: verified records + derived social state.
#[derive(Serialize, Deserialize, Default)]
pub struct StoredFeed {
    /// Raw signed records, in arrival order (the log).
    pub records: Vec<crate::records::Record>,
    /// Audience keys of other authors we hold (opened on follow accept).
    /// Stored as pairs: JSON map keys must be strings, and `PubKey`
    /// serializes as bytes.
    pub audience_keys: Vec<(PubKey, SymKey)>,
}

/// A directory on disk holding the identity file and the feed snapshot.
pub struct DeviceStore {
    dir: PathBuf,
}

impl DeviceStore {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn identity_path(&self) -> PathBuf {
        self.dir.join("identity.json")
    }

    pub fn feed_path(&self) -> PathBuf {
        self.dir.join("feed.json")
    }

    pub fn has_identity(&self) -> bool {
        self.identity_path().exists()
    }

    pub fn load_or_create_identity(&self, handle: String, display_name: String) -> Result<StoredIdentity, StoreError> {
        if self.has_identity() {
            let raw = std::fs::read(self.identity_path())?;
            Ok(serde_json::from_slice(&raw)?)
        } else {
            let id = StoredIdentity::create(handle, display_name);
            self.save_identity(&id)?;
            Ok(id)
        }
    }

    pub fn save_identity(&self, id: &StoredIdentity) -> Result<(), StoreError> {
        let json = serde_json::to_vec_pretty(id)?;
        std::fs::write(self.identity_path(), json)?;
        Ok(())
    }

    pub fn load_feed(&self) -> Result<StoredFeed, StoreError> {
        if !self.feed_path().exists() {
            return Ok(StoredFeed::default());
        }
        let raw = std::fs::read(self.feed_path())?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub fn save_feed(&self, feed: &StoredFeed) -> Result<(), StoreError> {
        let json = serde_json::to_vec(feed)?;
        std::fs::write(self.feed_path(), json)?;
        Ok(())
    }

    /// Persist derived audience keys plus a caller-maintained record log.
    pub fn persist(&self, records: &[crate::records::Record], feed: &Feed) -> Result<(), StoreError> {
        let stored = StoredFeed {
            records: records.to_vec(),
            audience_keys: feed
                .audience_keys
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        };
        let json = serde_json::to_vec(&stored)?;
        std::fs::write(self.feed_path(), json)?;
        Ok(())
    }

    /// Rebuild the live [`Feed`] from the persisted record log.
    pub fn replay(&self, me: Option<PubKey>) -> Result<(Feed, Vec<crate::feed::FeedEvent>), StoreError> {
        let stored = self.load_feed()?;
        let mut feed = Feed::new(me);
        let mut events = vec![];
        for rec in &stored.records {
            if let Ok(mut evs) = feed.apply(rec) {
                events.append(&mut evs);
            }
        }
        feed.audience_keys = stored.audience_keys.into_iter().collect();
        Ok((feed, events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip() {
        let dir = std::env::temp_dir().join(format!("social67-test-{}", std::process::id()));
        let store = DeviceStore::new(&dir).unwrap();
        let id = store.load_or_create_identity("jtg".into(), "Jose".into()).unwrap();
        let id2 = store.load_or_create_identity("other".into(), "Other".into()).unwrap();
        assert_eq!(id.device_sign, id2.device_sign); // persisted, not regenerated
        assert!(id.device().unwrap().verify().is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn feed_replay_rebuilds_state() {
        let dir = std::env::temp_dir().join(format!("social67-feed-{}", std::process::id()));
        let store = DeviceStore::new(&dir).unwrap();
        let mut stored = store.load_feed().unwrap();
        let root = RootIdentity::generate();
        let dev = DeviceIdentity::new_for(&root);
        let post = crate::feed::Feed::new(Some(root.root_pub()))
            .build_post(&dev, [1; 32], [2; 32], "hi", crate::records::Audience::Public, &SymKey::generate(), &crate::keys::EscrowIdentity::generate().public(), 1)
            .unwrap();
        stored.records.push(crate::records::Record::Post(post));
        std::fs::write(store.feed_path(), serde_json::to_vec(&stored).unwrap()).unwrap();
        let (feed, events) = store.replay(None).unwrap();
        assert_eq!(feed.posts.len(), 1);
        assert!(events.iter().any(|e| matches!(e, crate::feed::FeedEvent::PostAdded { .. })));
        std::fs::remove_dir_all(&dir).ok();
    }
}