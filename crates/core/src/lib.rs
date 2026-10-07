//! 67Social shared Rust core.
//!
//! One core for every device: phones, desktops, and the headless node are
//! all this crate with different front ends. Storage nodes are untrusted
//! and only ever hold ciphertext.
//!
//! Modules:
//! - [`crypto`]: XChaCha20-Poly1305 content encryption; HPKE-style key seals.
//! - [`keys`]: root / device / escrow key hierarchy and Ed25519 signing.
//! - [`records`]: the signed record model (posts, reactions, revocations,
//!   requests, directory entries, governance).
//! - [`ingest`]: image validation, EXIF stripping, normalization.
//! - [`feed`]: verified record application, audiences, aggregation, unlink.
//! - [`store`]: identity + feed persistence.
//! - [`net`]: Iroh transport — iroh-blobs, iroh-gossip, direct chat streams.

pub mod admin;
pub mod crypto;
pub mod feed;
pub mod ingest;
pub mod keys;
pub mod net;
pub mod records;
pub mod session;
pub mod store;

/// Unix time in milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Compute the stable id of a post from its blob references.
pub fn post_id(blob_hash: &[u8; 32], thumb_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"67social-post-v1");
    h.update(blob_hash);
    h.update(thumb_hash);
    *h.finalize().as_bytes()
}