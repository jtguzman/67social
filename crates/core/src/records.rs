//! The core data model: signed records.
//!
//! Every record is signed by its author's device key (directory entries and
//! governance records by the root / admin keys respectively) and verifiable
//! by any node without trusting whoever relayed it.
//!
//! Signable payloads are serialized with postcard (deterministic compact
//! binary), signed with Ed25519, and transported as a signed `Envelope`.
//! Records also derive `Serialize`/`Deserialize` for JSON use in the UI.

use serde::{Deserialize, Serialize};

use crate::crypto::{aead_open, aead_seal, seal_open, seal_to, EncryptPub, SymKey};
use crate::keys::{DeviceIdentity, PubKey};

pub type Hash = [u8; 32];
pub type RootId = PubKey;

/// A record wrapped with its signer's device/root key and signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope<T> {
    pub payload: T,
    /// Ed25519 verifying key of the signer (device key, root key, or admin key).
    pub signer: PubKey,
    /// X25519 public encryption key of the signer (for HPKE-style replies).
    pub enc_pub: EncryptPub,
    /// Root device certificate: root's signature over (signer || enc_pub).
    /// `None` when the signer *is* the root.
    pub cert: Option<CertSig>,
    pub signature: SigBytes,
}

/// Root certification of a device key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CertSig(pub Vec<u8>);

/// Ed25519 signature bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SigBytes(pub Vec<u8>);

impl<T: Serialize> Envelope<T> {
    /// Sign `payload` with a device identity.
    pub fn sign_with_device(payload: T, device: &DeviceIdentity) -> Self {
        let bytes = postcard::to_allocvec(&payload).expect("postcard serialization of record");
        Envelope {
            payload,
            signer: device.device_pub(),
            enc_pub: device.encrypt_pub(),
            cert: Some(CertSig(device.root_signature.to_vec())),
            signature: SigBytes(device.sign_payload(&bytes).to_vec()),
        }
    }

    /// Sign `payload` with an arbitrary key (root or admin key) with no
    /// device certificate — used for directory entries and governance.
    pub fn sign_with_key(payload: T, key: &crate::keys::PrivKey, enc_pub: EncryptPub) -> Self {
        let bytes = postcard::to_allocvec(&payload).expect("postcard serialization of record");
        Envelope {
            payload,
            signer: key.public(),
            enc_pub,
            cert: None,
            signature: SigBytes(key.sign(&bytes).to_vec()),
        }
    }

    /// Verify the envelope signature and device certificate against the
    /// claimed root.
    pub fn verify(&self, root: &PubKey) -> Result<(), crate::keys::KeyError>
    where
        T: Serialize,
    {
        let bytes = postcard::to_allocvec(&self.payload).expect("postcard serialization of record");
        crate::keys::PrivKey::verify(&self.signer, &bytes, &self.signature.0)?;
        match &self.cert {
            Some(cert) => DeviceIdentity::verify_device_of(root, &self.signer, &self.enc_pub, &cert.0),
            // Envelope signed directly by the root key itself.
            None => {
                if self.signer != *root {
                    return Err(crate::keys::KeyError::BadSignature);
                }
                Ok(())
            }
        }
    }
}

/// Which circle a post / reaction belongs to. The MVP has one audience per
/// user ("Followers"); custom circles slot in later as extra variants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Audience {
    /// Anyone may decrypt: the content key sits in the record unwrapped.
    Public,
    /// Members of `author`'s Followers circle; content key wrapped to the
    /// circle's symmetric audience key.
    Followers { author: RootId },
}

/// A symmetric key sealed (HPKE-style) to a recipient's public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SealedKey {
    /// `eph_pub || ct || tag`.
    pub sealed: Vec<u8>,
}

impl SealedKey {
    pub fn seal(recipient: &EncryptPub, key: &SymKey) -> Result<Self, crate::crypto::CryptoError> {
        Ok(Self {
            sealed: seal_to(recipient, key.as_bytes())?,
        })
    }

    pub fn open(&self, private: &crate::crypto::EncryptPriv) -> Result<SymKey, crate::crypto::CryptoError> {
        let bytes = seal_open(private, &self.sealed)?;
        SymKey::from_bytes(&bytes)
    }
}

/// A symmetric key wrapped with another symmetric key (e.g. content key
/// wrapped to the audience key): `nonce || ct || tag`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WrappedKey {
    pub wrapped: Vec<u8>,
}

impl WrappedKey {
    pub fn wrap(wrapping: &SymKey, key: &SymKey) -> Self {
        Self {
            wrapped: aead_seal(wrapping, key.as_bytes(), b"content-key"),
        }
    }

    pub fn unwrap(&self, wrapping: &SymKey) -> Result<SymKey, crate::crypto::CryptoError> {
        aead_open(wrapping, &self.wrapped, b"content-key").and_then(|b| SymKey::from_bytes(&b))
    }
}

/// Caption payload: plaintext for public posts, encrypted alongside the
/// image for private audiences — as protected as the photo it describes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Caption {
    Plain(String),
    Sealed(WrappedKey),
}

/// The three default reaction scales, each rated 1–5. No free text.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Scale {
    Stars = 0,
    Hearts = 1,
    Fire = 2,
}

impl Scale {
    pub const ALL: [Scale; 3] = [Scale::Stars, Scale::Hearts, Scale::Fire];

    pub fn from_u8(v: u8) -> Option<Scale> {
        match v {
            0 => Some(Scale::Stars),
            1 => Some(Scale::Hearts),
            2 => Some(Scale::Fire),
            _ => None,
        }
    }

    pub fn emoji(&self) -> char {
        match self {
            Scale::Stars => '★',
            Scale::Hearts => '❤',
            Scale::Fire => '🔥',
        }
    }
}

/// Content-key material in the record: public posts carry the content key
/// unwrapped; private posts wrap it to the circle's audience key. Escrow
/// always gets a second seal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyMaterial {
    /// Public post: anyone may decrypt.
    Plain(SymKey),
    /// Private post: content key wrapped to the audience key.
    Audience(WrappedKey),
}

/// A post: signed record authored on a device — the encrypted image
/// reference, optional caption, audience, wrapped content keys, timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PostRecord {
    /// BLAKE3 of the full-image blob hash + thumbnail hash (stable id).
    pub id: Hash,
    /// Author's root key (the account).
    pub author: RootId,
    pub blob_hash: Hash,
    pub thumb_hash: Hash,
    pub caption: Caption,
    pub audience: Audience,
    pub key_material: KeyMaterial,
    /// Content key wrapped to the author's escrow public key.
    pub wrapped_escrow: SealedKey,
    /// Unix millis.
    pub created_at: u64,
}

/// A reaction: tiny signed record `{ post, rater, scale, value 1–5, ts }`.
/// Last-writer-wins per (rater, scale). Ratings on private posts are sealed
/// to the post's audience.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReactionRecord {
    pub post_id: Hash,
    pub rater: RootId,
    pub body: ReactionBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReactionBody {
    /// Public post: rating visible to everyone.
    Plain { scale: Scale, value: u8, created_at: u64 },
    /// Private post: sealed to the post's audience key.
    Sealed { sealed: Vec<u8> },
}

impl ReactionBody {
    pub fn seal_plain(audience_key: &SymKey, scale: Scale, value: u8, created_at: u64) -> Self {
        let inner = ReactionBody::Plain {
            scale,
            value,
            created_at,
        };
        let sealed = aead_seal(audience_key, &postcard::to_allocvec(&inner).expect("serialize"), b"reaction");
        ReactionBody::Sealed { sealed }
    }

    pub fn open_sealed(&self, audience_key: &SymKey) -> Option<ReactionBody> {
        match self {
            ReactionBody::Plain { .. } => Some(self.clone()),
            ReactionBody::Sealed { sealed } => {
                let bytes = aead_open(audience_key, sealed, b"reaction").ok()?;
                postcard::from_bytes(&bytes).ok()
            }
        }
    }
}

/// Signed revocation ("unlink") — crypto-shredding: the author destroys the
/// content key; nodes drop the chunks at the next GC pass. The network
/// stops distributing it and no one new can open it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RevocationRecord {
    /// The post's author (only they may unlink it).
    pub author: RootId,
    pub post_id: Hash,
    pub blob_hash: Hash,
    pub thumb_hash: Hash,
    pub created_at: u64,
}

/// Follow request. Accepting delivers the "Followers" audience key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FollowRequest {
    pub from: RootId,
    pub to: RootId,
    pub created_at: u64,
}

/// Decision on a follow request. On accept, the current Followers audience
/// key is sealed (HPKE-style) to the requester's public encryption key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FollowDecision {
    /// The author deciding (root key) — lets the recipient verify the
    /// signer's device certificate against the right root.
    pub author: RootId,
    pub to: RootId, // the original requester
    pub accepted: bool,
    /// Present iff accepted: the author's current audience key, sealed to
    /// the new follower.
    pub audience_delivery: Option<SealedKey>,
    /// Which audience version was delivered (rotation tracking).
    pub audience_version: u32,
    pub created_at: u64,
}

/// Message request — a separate gate from following. Declined message
/// requests are simply dropped; blocking prevents re-request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageRequest {
    pub from: RootId,
    pub to: RootId,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageDecision {
    pub author: RootId,
    pub to: RootId,
    pub accepted: bool,
    pub created_at: u64,
}

/// Public-safe directory entry: root key, device keys, handle, display
/// name, serving nodes. Nothing private — no follower lists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirectoryEntry {
    pub root: RootId,
    pub handle: String,
    pub display_name: String,
    pub devices: Vec<DevicePubLite>,
    pub escrow_pub: EncryptPub,
    /// Endpoint ids (as strings) that serve this account's blobs — the
    /// author's own devices for the MVP.
    pub serving_nodes: Vec<String>,
    pub updated_at: u64,
}

/// Device entry in the directory (cert material without full signature
/// duplication of [`crate::keys::DevicePub`], kept compact).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DevicePubLite {
    pub sign_pub: PubKey,
    pub enc_pub: EncryptPub,
}

impl DirectoryEntry {
    /// Directory entries are signed by the *root* key (cert: None).
    pub fn sign(&self, root: &crate::keys::RootIdentity, enc_pub: EncryptPub) -> Envelope<DirectoryEntry> {
        Envelope::sign_with_key(self.clone(), &root.key, enc_pub)
    }

    pub fn verify(&self, env: &Envelope<DirectoryEntry>) -> Result<(), crate::keys::KeyError> {
        env.verify(&self.root)
    }
}

/// Governance record signed by the admin key: suspension, device-key
/// revocation, content-hash blocklist, handle binding. Real control that
/// never touches a photo.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GovernanceRecord {
    pub action: GovernanceAction,
    pub admin: PubKey,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GovernanceAction {
    /// Suspend an account: clients refuse to sync/display its content.
    Suspend { root: RootId, reason: String },
    /// Lift a suspension.
    Reinstate { root: RootId },
    /// Blocklist a content hash (illegal material); nodes drop the blob.
    Blocklist { hash: Hash, reason: String },
    /// Registrar: settle @handle ties, binding handle → root key.
    BindHandle { handle: String, root: RootId },
}

/// Everything that can ride the gossip topic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Record {
    Post(Envelope<PostRecord>),
    Reaction(Envelope<ReactionRecord>),
    Revocation(Envelope<RevocationRecord>),
    FollowRequest(Envelope<FollowRequest>),
    FollowDecision(Envelope<FollowDecision>),
    MessageRequest(Envelope<MessageRequest>),
    MessageDecision(Envelope<MessageDecision>),
    Directory(Envelope<DirectoryEntry>),
    Governance(Envelope<GovernanceRecord>),
}

impl Record {
    /// The root account this record is addressed to or concerns.
    pub fn roots_involved(&self) -> Vec<RootId> {
        match self {
            Record::Post(e) => vec![e.payload.author],
            Record::Reaction(e) => vec![e.payload.rater],
            Record::Revocation(e) => vec![e.signer],
            Record::FollowRequest(e) => vec![e.payload.from, e.payload.to],
            Record::FollowDecision(e) => vec![e.payload.to, e.signer],
            Record::MessageRequest(e) => vec![e.payload.from, e.payload.to],
            Record::MessageDecision(e) => vec![e.payload.to, e.signer],
            Record::Directory(e) => vec![e.payload.root],
            Record::Governance(e) => vec![e.payload.admin],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DeviceIdentity, PrivKey, RootIdentity};

    fn sample_post() -> PostRecord {
        let content = SymKey::generate();
        let audience_key = SymKey::generate();
        let esc = crate::keys::EscrowIdentity::generate();
        PostRecord {
            id: [7u8; 32],
            author: PubKey([1; 32]),
            blob_hash: [2; 32],
            thumb_hash: [3; 32],
            caption: Caption::Plain("hello".into()),
            audience: Audience::Followers { author: PubKey([1; 32]) },
            key_material: KeyMaterial::Audience(WrappedKey::wrap(&audience_key, &content)),
            wrapped_escrow: SealedKey::seal(&esc.public(), &content).unwrap(),
            created_at: 1_700_000_000_000,
        }
    }

    #[test]
    fn post_envelope_sign_verify_roundtrip() {
        let root = RootIdentity::generate();
        let dev = DeviceIdentity::new_for(&root);
        let post = sample_post();
        let env = Envelope::sign_with_device(post.clone(), &dev);

        // Valid: correct root.
        env.verify(&root.root_pub()).unwrap();
        // Invalid: wrong root.
        let other = RootIdentity::generate();
        assert!(env.verify(&other.root_pub()).is_err());

        // Tamper with payload → signature fails.
        let mut env2 = env.clone();
        env2.payload.created_at += 1;
        assert!(env2.verify(&root.root_pub()).is_err());
    }

    #[test]
    fn wrapped_key_roundtrip() {
        let wrapping = SymKey::generate();
        let content = SymKey::generate();
        let wrapped = WrappedKey::wrap(&wrapping, &content);
        assert_eq!(wrapped.unwrap(&wrapping).unwrap(), content);
        assert!(wrapped.unwrap(&SymKey::generate()).is_err());
    }

    #[test]
    fn reaction_seal_open_roundtrip() {
        let audience_key = SymKey::generate();
        let sealed = ReactionBody::seal_plain(&audience_key, Scale::Stars, 5, 42);
        let opened = sealed.open_sealed(&audience_key).unwrap();
        match opened {
            ReactionBody::Plain { scale, value, created_at } => {
                assert_eq!(scale, Scale::Stars);
                assert_eq!(value, 5);
                assert_eq!(created_at, 42);
            }
            _ => panic!("expected plain"),
        }
        assert!(sealed.open_sealed(&SymKey::generate()).is_none());
    }

    #[test]
    fn record_postcard_roundtrip() {
        let root = RootIdentity::generate();
        let dev = DeviceIdentity::new_for(&root);
        let env = Envelope::sign_with_device(sample_post(), &dev);
        let rec = Record::Post(env);
        let bytes = postcard::to_allocvec(&rec).unwrap();
        let back: Record = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn directory_entry_signed_by_root() {
        let root = RootIdentity::generate();
        let entry = DirectoryEntry {
            root: root.root_pub(),
            handle: "jtg".into(),
            display_name: "Jose".into(),
            devices: vec![],
            escrow_pub: crate::keys::EscrowIdentity::generate().public(),
            serving_nodes: vec![],
            updated_at: 1,
        };
        let env = entry.sign(&root, root.encrypt.public());
        env.verify(&root.root_pub()).unwrap();
        let other = RootIdentity::generate();
        assert!(env.verify(&other.root_pub()).is_err());
        assert!(PrivKey::verify(&root.root_pub(), b"tampered", &env.signature.0).is_err());
    }
}