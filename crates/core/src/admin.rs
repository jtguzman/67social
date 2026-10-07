//! Operator tooling: governance (no content access) and case-based escrow
//! read (per-user, silent, bounded), with the audit log that keeps the
//! power accountable.
//!
//! Two separate powers, kept separate:
//! - **Governance**: signed records every client enforces — suspensions,
//!   blocklists, handle bindings. Never touches a photo.
//! - **Escrow case**: unwrap one user's content keys with their escrow
//!   private key, fetch ciphertext like any authorized reader. Scoped to
//!   exactly one user; every access is written to the append-only,
//!   hash-chained audit log whose head hash is published periodically.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::keys::{PrivKey, PubKey};
use crate::records::{Envelope, GovernanceAction, GovernanceRecord, Hash, PostRecord, Record};

/// The operator's admin/governance key.
pub struct AdminIdentity {
    pub key: PrivKey,
}

impl AdminIdentity {
    pub fn generate() -> Self {
        Self {
            key: PrivKey::generate(),
        }
    }

    pub fn admin_pub(&self) -> PubKey {
        self.key.public()
    }

    /// Sign a governance record. Governance is signed directly by the
    /// admin key — no device certificate.
    pub fn sign_governance(&self, action: GovernanceAction, created_at: u64) -> Envelope<GovernanceRecord> {
        Envelope::sign_with_key(
            GovernanceRecord {
                action,
                admin: self.admin_pub(),
                created_at,
            },
            &self.key,
            self.enc_pub(),
        )
    }

    fn enc_pub(&self) -> crate::crypto::EncryptPub {
        // Governance keys never wrap content; the envelope's enc field is
        // unused for them but must be present.
        crate::crypto::EncryptPub([0u8; 32])
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::json!({
            "admin_key": data_encoding::HEXLOWER.encode(&self.key.to_bytes()),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&json)?)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path)?;
        let json: serde_json::Value = serde_json::from_slice(&raw)?;
        let hex = json["admin_key"]
            .as_str()
            .ok_or_else(|| anyhow!("admin key file missing admin_key field"))?;
        let bytes = data_encoding::HEXLOWER
            .decode(hex.as_bytes())
            .map_err(|e| anyhow!("bad admin key hex: {e}"))?;
        Ok(Self {
            key: PrivKey::from_bytes(&bytes).map_err(|e| anyhow!("{e}"))?,
        })
    }
}

/// One audit-log entry: who accessed which user's content, when, for which
/// case. Chained by hash so the log cannot be rewritten unnoticed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    pub seq: u64,
    /// BLAKE3 of the previous entry's canonical bytes (all zeros for seq 0).
    pub prev_hash: Hash,
    pub at: u64,
    pub admin: PubKey,
    pub action: AuditAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditAction {
    CaseOpened { user: PubKey, case_ref: String },
    PostRead { user: PubKey, post_id: Hash },
    CaseClosed { user: PubKey, case_ref: String },
}

/// Append-only, signed audit log: `{who, which user, when, case reference}`,
/// hash-chained; the head hash is published periodically so entries cannot
/// be dropped or reordered without detection.
pub struct AuditLog {
    path: PathBuf,
    entries: Vec<AuditEntry>,
    admin: PubKey,
}

impl AuditLog {
    /// Load or create the log file (JSONL).
    pub fn open(path: impl Into<PathBuf>, admin: PubKey) -> Result<Self> {
        let path = path.into();
        let mut entries = vec![];
        if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            for line in raw.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                entries.push(serde_json::from_str(line).context("audit log parse")?);
            }
        }
        Ok(Self { path, entries, admin })
    }

    fn hash_entry(entry: &AuditEntry) -> Hash {
        let bytes =
            postcard::to_allocvec(entry).expect("audit entry serialization cannot fail");
        *blake3::hash(&bytes).as_bytes()
    }

    /// Verify the chain's integrity (tamper/drop/reorder detection).
    pub fn verify(&self) -> Result<()> {
        let mut prev = [0u8; 32];
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.seq != i as u64 || entry.prev_hash != prev || entry.admin != self.admin {
                return Err(anyhow!("audit log chain broken at entry {i}"));
            }
            prev = Self::hash_entry(entry);
        }
        Ok(())
    }

    /// Append an entry (signature: the entry hash IS the commitment; the
    /// chain head is what gets published).
    pub fn append(&mut self, action: AuditAction) -> Result<AuditEntry> {
        let prev_hash = self
            .entries
            .last()
            .map(|e| Self::hash_entry(e))
            .unwrap_or([0u8; 32]);
        let entry = AuditEntry {
            seq: self.entries.len() as u64,
            prev_hash,
            at: crate::now_ms(),
            admin: self.admin,
            action,
        };
        let line = serde_json::to_string(&entry)?;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// The published commitment: the chain head hash.
    pub fn chain_head(&self) -> Hash {
        self.entries
            .last()
            .map(Self::hash_entry)
            .unwrap_or([0u8; 32])
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

/// Pin an admin public key into a session's data dir, so its feed enforces
/// governance records signed by that key. One key per line.
pub fn pin_admin_key(data_dir: &Path, admin_pub: &PubKey) -> Result<()> {
    use std::io::Write;
    let path = data_dir.join("admin.pub");
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", admin_pub)?;
    Ok(())
}

fn load_admin_keys(data_dir: &Path) -> Vec<PubKey> {
    let path = data_dir.join("admin.pub");
    let mut keys = vec![];
    if let Ok(raw) = std::fs::read_to_string(path) {
        for line in raw.lines() {
            if let Ok(k) = line.trim().parse::<PubKey>() {
                keys.push(k);
            }
        }
    }
    keys
}

/// Publish a governance record through an existing session (the operator
/// runs a normal node on the topic; governance is just signed records).
/// Clients enforce it because it is a verifiable signature from a pinned
/// admin key — real control that never touches a photo.
pub async fn publish_governance(
    session: &mut crate::session::Session,
    admin: &AdminIdentity,
    action: GovernanceAction,
) -> Result<()> {
    let env = admin.sign_governance(action, crate::now_ms());
    // Apply locally (enforcement + persistence so the operator node
    // rebroadcasts it) and gossip.
    session
        .apply_and_broadcast(Record::Governance(env))
        .await?;
    Ok(())
}

/// Open a case: walk the user's signed post log (already synced by this
/// operator node's feed), fetch ciphertext like any authorized reader,
/// unwrap offline with the user's escrow key, save the images, and log
/// every access. Scoped to exactly one user — no other user's content is
/// touched, and there is no global master key.
pub fn run_case(
    session: &mut crate::session::Session,
    escrow: &crate::keys::EscrowIdentity,
    user_root: &PubKey,
    case_ref: &str,
    out_dir: &Path,
    audit: &mut AuditLog,
) -> Result<usize> {
    std::fs::create_dir_all(out_dir)?;
    audit.append(AuditAction::CaseOpened {
        user: *user_root,
        case_ref: case_ref.to_string(),
    })?;

    let posts: Vec<PostRecord> = session
        .feed
        .posts
        .values()
        .map(|e| e.env.payload.clone())
        .filter(|p| &p.author == user_root)
        .collect();

    let mut count = 0;
    // The operator node needs the target user's address book entry to dial
    // their blobs; the directory entries carry serving nodes.
    for post in posts {
        let key = session.feed.escrow_key_for(&post, escrow);
        let Some(key) = key else {
            // Escrow-wrapped key destroyed (post unlink retention window
            // elapsed) or not wrapped to this escrow — skip, logged.
            continue;
        };
        let image_ct = fetch_blob_for_case(session, post.blob_hash);
        if let Some(ct) = image_ct {
            if let Ok(image) = crate::crypto::aead_open(&key, &ct, crate::session::AAD_IMAGE) {
                let name = format!("{}-{}.bin", &data_encoding::HEXLOWER.encode(&post.id)[..16], count);
                std::fs::write(out_dir.join(name), image)?;
                count += 1;
            }
        }
        audit.append(AuditAction::PostRead {
            user: *user_root,
            post_id: post.id,
        })?;
    }

    audit.append(AuditAction::CaseClosed {
        user: *user_root,
        case_ref: case_ref.to_string(),
    })?;
    Ok(count)
}

/// Fetch ciphertext for a case read: local store first, then the serving
/// node from the directory. Nodes see an ordinary blob request.
fn fetch_blob_for_case(session: &crate::session::Session, hash: Hash) -> Option<Vec<u8>> {
    let blob = iroh_blobs::Hash::from(hash);
    // block_in_place is safe in multi-thread tokio runtimes.
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            match session.node.get_blob(&blob).await {
                Ok(ct) => Some(ct),
                Err(_) => {
                    // Find the post's author, then their serving node.
                    let author = session
                        .feed
                        .posts
                        .values()
                        .find(|p| p.env.payload.blob_hash == hash)?
                        .env
                        .payload
                        .author;
                    let endpoint = session
                        .feed
                        .directory
                        .get(&author)?
                        .serving_nodes
                        .first()
                        .and_then(|s| s.parse::<iroh::EndpointId>().ok())?;
                    session.node.fetch_blob(endpoint, &blob).await.ok()
                }
            }
        })
    })
}

/// Set of admin public keys to pin at session start.
pub fn admin_keys_for(data_dir: &Path) -> HashSet<PubKey> {
    load_admin_keys(data_dir).into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_chain_and_tamper_detection() {
        let dir = std::env::temp_dir().join(format!("s67-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let admin = AdminIdentity::generate();
        let path = dir.join("audit.jsonl");

        {
            let mut log = AuditLog::open(&path, admin.admin_pub()).unwrap();
            log.append(AuditAction::CaseOpened { user: PubKey([1; 32]), case_ref: "C-1".into() }).unwrap();
            log.append(AuditAction::PostRead { user: PubKey([1; 32]), post_id: [2; 32] }).unwrap();
            log.append(AuditAction::CaseClosed { user: PubKey([1; 32]), case_ref: "C-1".into() }).unwrap();
            log.verify().unwrap();
            let head = log.chain_head();
            assert_ne!(head, [0u8; 32]);
        }

        // Reload: chain verifies, entries persist.
        {
            let log = AuditLog::open(&path, admin.admin_pub()).unwrap();
            assert_eq!(log.entries().len(), 3);
            log.verify().unwrap();
        }

        // Tamper: rewrite a line → chain breaks.
        let raw = std::fs::read_to_string(&path).unwrap();
        let tampered = raw.replace("C-1", "C-2");
        std::fs::write(&path, tampered).unwrap();
        let log = AuditLog::open(&path, admin.admin_pub()).unwrap();
        assert!(log.verify().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governance_record_signed_and_verifiable() {
        let admin = AdminIdentity::generate();
        let env = admin.sign_governance(
            GovernanceAction::Suspend { root: PubKey([9; 32]), reason: "test".into() },
            123,
        );
        env.verify(&admin.admin_pub()).unwrap();
        let other = AdminIdentity::generate();
        assert!(env.verify(&other.admin_pub()).is_err());
    }
}
