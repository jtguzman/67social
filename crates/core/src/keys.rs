//! Identity and keys.
//!
//! Five key kinds, each with one job (see the design document):
//! - **Root identity**: signs device keys and the user's directory record.
//!   Never touches a storage node.
//! - **Device key**: signs posts and actions; the Iroh endpoint's identity.
//! - **Audience key**: symmetric; wraps per-post content keys for a circle.
//! - **Escrow key**: per-user X25519 keypair; a second lock on every content
//!   key for compliance access, scoped to one user only.
//! - **Admin / governance**: signs governance records; reads no content.
//!
//! No single key both authenticates a user and reads their content.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{EncryptPriv, EncryptPub, KEY_LEN};

pub const ED25519_PUB_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid ed25519 key bytes")]
    InvalidEd25519,
    #[error("signature verification failed")]
    BadSignature,
}

/// Ed25519 verifying (public) key wrapper with serde.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PubKey(pub [u8; ED25519_PUB_LEN]);

impl PubKey {
    pub fn from_bytes(b: &[u8]) -> Result<Self, KeyError> {
        let arr: [u8; ED25519_PUB_LEN] = b
            .try_into()
            .map_err(|_| KeyError::InvalidEd25519)?;
        Ok(Self(arr))
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, KeyError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| KeyError::InvalidEd25519)
    }

    /// Short stable identifier for display (10 lowercase base32 chars).
    pub fn short(&self) -> String {
        let b32 = data_encoding::BASE32_NOPAD.encode(&self.0[..7]);
        b32[..10].to_lowercase()
    }
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PubKey({})", self.short())
    }
}

impl std::fmt::Display for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", data_encoding::HEXLOWER.encode(&self.0))
    }
}

impl std::str::FromStr for PubKey {
    type Err = KeyError;
    fn from_str(s: &str) -> Result<Self, KeyError> {
        let bytes = data_encoding::HEXLOWER
            .decode(s.trim().as_bytes())
            .map_err(|_| KeyError::InvalidEd25519)?;
        PubKey::from_bytes(&bytes)
    }
}

impl Serialize for PubKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8> as Deserialize>::deserialize(d)?;
        PubKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Ed25519 signing key wrapper. Never serialized; persisted as raw bytes
/// by the owning device only.
#[derive(Clone)]
pub struct PrivKey(SigningKey);

impl PrivKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; ED25519_PUB_LEN];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, KeyError> {
        let arr: [u8; ED25519_PUB_LEN] = b
            .try_into()
            .map_err(|_| KeyError::InvalidEd25519)?;
        Ok(Self(SigningKey::from_bytes(&arr)))
    }

    pub fn to_bytes(&self) -> [u8; ED25519_PUB_LEN] {
        self.0.to_bytes()
    }

    pub fn public(&self) -> PubKey {
        PubKey(self.0.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; ED25519_SIG_LEN] {
        self.0.sign(msg).to_bytes()
    }

    pub fn verify(pubkey: &PubKey, msg: &[u8], sig: &[u8]) -> Result<(), KeyError> {
        let sig: [u8; ED25519_SIG_LEN] = sig
            .try_into()
            .map_err(|_| KeyError::BadSignature)?;
        pubkey
            .verifying_key()?
            .verify(msg, &Signature::from_bytes(&sig))
            .map_err(|_| KeyError::BadSignature)
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivKey(..)")
    }
}

/// A user's root identity: the account anchor. Backed up offline; the root
/// key never touches a storage node.
pub struct RootIdentity {
    pub key: PrivKey,
    /// Long-lived encryption keypair for key delivery (HPKE-style seals).
    pub encrypt: EncryptPriv,
}

impl RootIdentity {
    pub fn generate() -> Self {
        Self {
            key: PrivKey::generate(),
            encrypt: EncryptPriv::generate(),
        }
    }

    pub fn root_pub(&self) -> PubKey {
        self.key.public()
    }
}

/// A device's full identity. Each device generates its own keys, signed by
/// the root; losing a phone never means losing the account.
pub struct DeviceIdentity {
    /// Signs posts and actions.
    pub signing: PrivKey,
    /// Static X25519 keypair: target for sealed audience-key delivery.
    pub encrypt: EncryptPriv,
    /// Signature by the root key over `device_sign_pub || device_enc_pub`.
    /// `Vec<u8>` rather than a fixed array because serde does not implement
    /// traits for arrays > 32 elements.
    pub root_signature: Vec<u8>,
    /// The root this device belongs to.
    pub root: PubKey,
}

impl DeviceIdentity {
    /// Create a device identity and have `root` certify it.
    pub fn new_for(root: &RootIdentity) -> Self {
        let signing = PrivKey::generate();
        let encrypt = EncryptPriv::generate();
        let mut msg = Vec::new();
        msg.extend_from_slice(&signing.public().0);
        msg.extend_from_slice(&encrypt.public().0);
        let root_signature = root.key.sign(&msg).to_vec();
        Self {
            signing,
            encrypt,
            root_signature,
            root: root.root_pub(),
        }
    }

    pub fn device_pub(&self) -> PubKey {
        self.signing.public()
    }

    pub fn encrypt_pub(&self) -> EncryptPub {
        self.encrypt.public()
    }

    /// Verify this device's certificate against the root key.
    pub fn verify(&self) -> Result<(), KeyError> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.device_pub().0);
        msg.extend_from_slice(&self.encrypt_pub().0);
        PrivKey::verify(&self.root, &msg, &self.root_signature)
    }

    pub fn sign_payload(&self, payload: &[u8]) -> [u8; ED25519_SIG_LEN] {
        self.signing.sign(payload)
    }

    /// Verify a payload signed by *another* device of the same root, using
    /// the device certificate: `device_pub` must be certified by `root`.
    pub fn verify_device_of(root: &PubKey, device_pub: &PubKey, enc_pub: &EncryptPub, cert_sig: &[u8]) -> Result<(), KeyError> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&device_pub.0);
        msg.extend_from_slice(&enc_pub.0);
        PrivKey::verify(root, &msg, cert_sig)
    }
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device", &self.device_pub())
            .field("root", &self.root)
            .finish()
    }
}

/// A device's public material as published in the directory entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevicePub {
    pub sign_pub: PubKey,
    pub enc_pub: EncryptPub,
    /// Root signature certifying this device (Vec: serde caps arrays at 32).
    pub cert: Vec<u8>,
    pub added_at: u64,
}

/// Per-user escrow keypair. Every content key the user produces is wrapped
/// to this public key as a second lock; opening a case on one user unlocks
/// only that user's content.
pub struct EscrowIdentity {
    pub private: EncryptPriv,
}

impl EscrowIdentity {
    pub fn generate() -> Self {
        Self {
            private: EncryptPriv::generate(),
        }
    }

    pub fn public(&self) -> EncryptPub {
        self.private.public()
    }

    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.private.to_bytes()
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, crate::crypto::CryptoError> {
        Ok(Self {
            private: EncryptPriv::from_bytes(b)?,
        })
    }
}

impl std::fmt::Debug for EscrowIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EscrowIdentity({:?})", self.public())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{seal_open, seal_to};

    #[test]
    fn device_certification_roundtrip() {
        let root = RootIdentity::generate();
        let dev = DeviceIdentity::new_for(&root);
        assert!(dev.verify().is_ok());
    }

    #[test]
    fn device_certification_rejects_uncertified_key() {
        // A device whose keys were swapped after certification fails.
        let root = RootIdentity::generate();
        let dev = DeviceIdentity::new_for(&root);
        let mut tampered = DeviceIdentity::new_for(&root);
        tampered.root_signature = dev.root_signature;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn signature_verify() {
        let k = PrivKey::generate();
        let sig = k.sign(b"payload");
        assert!(PrivKey::verify(&k.public(), b"payload", &sig).is_ok());
        assert!(PrivKey::verify(&k.public(), b"other", &sig).is_err());
    }

    #[test]
    fn escrow_seal_opens_only_with_escrow_priv() {
        let esc = EscrowIdentity::generate();
        let other = EscrowIdentity::generate();
        let sealed = seal_to(&esc.public(), b"content key").unwrap();
        assert_eq!(seal_open(&esc.private, &sealed).unwrap(), b"content key");
        assert!(seal_open(&other.private, &sealed).is_err());
    }
}