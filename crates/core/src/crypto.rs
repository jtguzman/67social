//! Cryptographic primitives for 67Social.
//!
//! - Content encryption: XChaCha20-Poly1305 with a random 24-byte nonce,
//!   keyed by a random per-post *content key*.
//! - Key sealing ("HPKE-style" KEM-DEM): X25519 ephemeral ECDH +
//!   HKDF-SHA256 + XChaCha20-Poly1305, sealed to a recipient's public
//!   encryption key. Used to deliver audience keys (follow acceptance) and
//!   to wrap content keys to the per-user escrow key.
//!
//! Everything here operates on raw bytes so it is transport-agnostic.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret as XStaticSecret};

/// Length of a symmetric content / audience key.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// X25519 public key length.
pub const X_PUB_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decryption failed (wrong key or corrupted ciphertext)")]
    DecryptFailed,
    #[error("key seal open failed")]
    SealOpenFailed,
    #[error("invalid key material")]
    InvalidKey,
}

/// A random symmetric key (content key, audience key).
#[derive(Clone, PartialEq, Eq)]
pub struct SymKey(pub [u8; KEY_LEN]);

impl SymKey {
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; KEY_LEN] = b
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        write!(f, "SymKey(..)")
    }
}

impl Serialize for SymKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SymKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8> as Deserialize>::deserialize(d)?;
        SymKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// An X25519 public key used as an encryption target.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EncryptPub(pub [u8; X_PUB_LEN]);

impl EncryptPub {
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; X_PUB_LEN] = b
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(arr))
    }
}

impl std::fmt::Debug for EncryptPub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptPub({})", data_encoding::HEXLOWER.encode(&self.0[..6]))
    }
}

impl Serialize for EncryptPub {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for EncryptPub {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8> as Deserialize>::deserialize(d)?;
        EncryptPub::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// The private side of an encryption keypair.
#[derive(Clone)]
pub struct EncryptPriv(XStaticSecret);

impl EncryptPriv {
    pub fn generate() -> Self {
        // x25519-dalek 2.x pins rand_core 0.6, which rand 0.9 does not
        // satisfy — use the OS-RNG constructor instead.
        Self(XStaticSecret::random())
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; X_PUB_LEN] = b
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(XStaticSecret::from(arr)))
    }

    pub fn public(&self) -> EncryptPub {
        EncryptPub(XPublicKey::from(&self.0).to_bytes())
    }

    pub fn to_bytes(&self) -> [u8; X_PUB_LEN] {
        self.0.to_bytes()
    }
}

impl std::fmt::Debug for EncryptPriv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptPriv(..)")
    }
}

/// Encrypt `plaintext` with a symmetric key. Returns `nonce || ct || tag`.
pub fn aead_seal(key: &SymKey, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).expect("32-byte key");
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail with valid inputs");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt `nonce || ct || tag` produced by [`aead_seal`].
pub fn aead_open(key: &SymKey, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE_LEN {
        return Err(CryptoError::DecryptFailed);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).expect("32-byte key");
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

/// HPKE-style single-shot seal to a recipient public key.
///
/// `output = eph_pub(32) || ct`, where
/// `key || nonce = HKDF-SHA256(ikm = ecdh(eph, recip), salt = eph_pub || recip_pub,
/// info = b"67social-hpke-v1")` (32-byte key, 24-byte nonce).
pub fn seal_to(recipient: &EncryptPub, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let eph = EphemeralSecret::random();
    let eph_pub = XPublicKey::from(&eph);
    let recip = XPublicKey::from(recipient.0);
    let shared = eph.diffie_hellman(&recip);

    let mut salt = Vec::with_capacity(X_PUB_LEN * 2);
    salt.extend_from_slice(eph_pub.as_bytes());
    salt.extend_from_slice(&recipient.0);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut okm = [0u8; KEY_LEN + NONCE_LEN];
    hk.expand(b"67social-hpke-v1", &mut okm)
        .expect("valid HKDF output length");
    let (key, nonce) = okm.split_at(KEY_LEN);

    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let ct = cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .expect("XChaCha20-Poly1305 encryption cannot fail with valid inputs");

    let mut out = Vec::with_capacity(X_PUB_LEN + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a seal produced by [`seal_to`] with the recipient private key.
pub fn seal_open(private: &EncryptPriv, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < X_PUB_LEN {
        return Err(CryptoError::SealOpenFailed);
    }
    let (eph_pub_bytes, ct) = sealed.split_at(X_PUB_LEN);
    let eph_arr: [u8; X_PUB_LEN] = eph_pub_bytes
        .try_into()
        .map_err(|_| CryptoError::SealOpenFailed)?;
    let eph_pub = XPublicKey::from(eph_arr);
    let shared = private.0.diffie_hellman(&eph_pub);

    let mut salt = Vec::with_capacity(X_PUB_LEN * 2);
    salt.extend_from_slice(eph_pub_bytes);
    salt.extend_from_slice(&private.public().0);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut okm = [0u8; KEY_LEN + NONCE_LEN];
    hk.expand(b"67social-hpke-v1", &mut okm)
        .expect("valid HKDF output length");
    let (key, nonce) = okm.split_at(KEY_LEN);

    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| CryptoError::SealOpenFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip() {
        let key = SymKey::generate();
        let sealed = aead_seal(&key, b"hello world", b"aad");
        assert_eq!(aead_open(&key, &sealed, b"aad").unwrap(), b"hello world");
        assert!(aead_open(&key, &sealed, b"other").is_err());
    }

    #[test]
    fn aead_wrong_key_fails() {
        let sealed = aead_seal(&SymKey::generate(), b"secret", b"");
        assert!(aead_open(&SymKey::generate(), &sealed, b"").is_err());
    }

    #[test]
    fn seal_roundtrip() {
        let priv1 = EncryptPriv::generate();
        let priv2 = EncryptPriv::generate();
        let sealed = seal_to(&priv1.public(), b"audience key bytes").unwrap();
        assert_eq!(seal_open(&priv1, &sealed).unwrap(), b"audience key bytes");
        assert!(seal_open(&priv2, &sealed).is_err());
    }

    #[test]
    fn seal_is_randomized() {
        let priv1 = EncryptPriv::generate();
        let s1 = seal_to(&priv1.public(), b"same").unwrap();
        let s2 = seal_to(&priv1.public(), b"same").unwrap();
        assert_ne!(s1, s2);
    }
}