# 67Social — MVP

An Instagram-style social network where images live encrypted across users' own devices instead of
a central host, are viewable only by people holding the right key, and can be truly unlinked by the
author. Feedback is reaction-only (1–5 ratings on three emoji scales, no text comments); following
and messaging are request-gated; accepted message requests open an ephemeral chat that persists only
in each device's local storage.

This repository implements the MVP specified in [`docs/mvp-design-document.md`](docs/mvp-design-document.md):
one shared Rust core, a headless storage node daemon, and a Tauri 2 + Svelte app.

## Layout

```
crates/core/    social67-core — the shared core (the only thing every device runs)
  src/crypto.rs    XChaCha20-Poly1305 content encryption; HPKE-style key seals
                   (X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305)
  src/keys.rs      root / device / escrow key hierarchy; Ed25519 signing
  src/records.rs   the signed record model (posts, reactions, revocations,
                   follow/message requests, directory entries, governance)
  src/feed.rs      verified record application: audiences, rotation, LWW
                   reaction aggregation, author-only unlink, request gates
  src/ingest.rs    decode-or-reject image validation, EXIF/GPS stripping,
                   2048px normalization + thumbnails
  src/store.rs     device-local identity + record-log persistence (chat is
                   deliberately NOT persisted here — localStorage only)
  src/net.rs       Iroh transport: iroh-blobs, iroh-gossip, direct chat streams,
                   GC keep-set (crypto-shredding enforcement)
  src/session.rs   the application layer shared by daemon and app
  src/admin.rs     audit log (hash-chained, append-only), governance signing,
                   case-based escrow read
  tests/e2e.rs     the Phase-0 spike as an integration test
crates/node/    social67-node — the headless, always-on storage node daemon
crates/admin/   social67-admin — the operator tool (governance + escrow cases)
app/            Tauri 2 shell + Svelte/TypeScript UI
```

## Trust model in one paragraph

Five key kinds, each with one job: a **root** key anchors the account and signs device keys;
a per-**device** key signs posts (losing a phone ≠ losing the account); a symmetric **audience**
key wraps per-post content keys so the Followers circle can decrypt (delivered once, HPKE-style,
when a follow is accepted; rotated when a follower is removed); a per-user **escrow** key is a
second lock on every content key, scoped to exactly one user; and the **admin/governance** key signs
suspensions, blocklists, and handle bindings but reads no content. Storage nodes are untrusted and
only ever hold BLAKE3-addressed ciphertext. Unlink is crypto-shredding: a signed revocation plus
key destruction — the network stops distributing the ciphertext and no one new can open it.

## Build & test

```bash
cargo test -p social67-core           # 32 unit + integration tests
cargo build -p social67-node -p social67-admin   # daemon + operator tool
cd app && pnpm install && pnpm build  # UI
pnpm tauri build --bundles deb        # desktop app + installer (~9 MiB, system WebView)
```

The integration test (`cargo test -p social67-core --test e2e`) proves the full trust model over a
real Iroh transport on localhost: directory discovery over gossip, encrypted post → fetch → decrypt,
replication, reaction aggregation, follow-gated private posts with HPPE key delivery, request-gated
chat over a direct QUIC stream, signed unlink, and rejection of non-author revocations.

## Running a two-node network by hand

Terminal 1 (starts a new network):

```bash
cargo run -p social67-node -- --data-dir /tmp/n1 --handle alice
# prints:  invite: <string>
```

Terminal 2 (joins via the invite):

```bash
cargo run -p social67-node -- --data-dir /tmp/n2 --handle bob --invite <string>
```

Both nodes mirror records, serve ciphertext blobs to authorized peers, and log what they see —
never any plaintext. The desktop app does the same with a UI: paste an invite on the onboarding
screen to join an existing network, or start a new one and share your own invite from the footer.
The daemon can also publish a demo post: `--demo-post /path/to/image.png --demo-caption "hi"`.

## The operator tool

```bash
cargo run -p social67-admin -- --data-dir /tmp/op keygen
# → writes admin.json (private) + admin.pub (copy this line into every node's data dir)

# Publish governance records — clients enforce them via signature:
cargo run -p social67-admin -- --data-dir /tmp/op --invite <string> govern suspend --root <hex> --reason "..."
cargo run -p social67-admin -- --data-dir /tmp/op --invite <string> govern blocklist --hash <hex> --reason "..."
cargo run -p social67-admin -- --data-dir /tmp/op --invite <string> govern bind-handle --handle alice --root <hex>

# Open a case: decrypt one user's content with their escrow key, fully audited:
cargo run -p social67-admin -- --data-dir /tmp/op --invite <string> case \
    --user-root <hex> --escrow-key escrow.hex --out ./case-output --case-ref C-001
# Every access is appended to audit.jsonl; verify + get the publishable chain head:
cargo run -p social67-admin -- --data-dir /tmp/op audit
```

Honest limits, restated: no global master key (a case unlocks exactly one user); time-boxing a
case requires the custody mediator (not built — escrow keys are non-expiring in this MVP); chat
content is not retrievable by anyone, including the operator; and a node that already holds a
tagged blob keeps serving it until a revocation record arrives and the GC pass sweeps it.

## Deferred, by design (see the doc)

Reed-Solomon erasure coding, proof-of-storage repair, storage-contribution quotas, custom circles,
capability tokens, threshold key custody for hard revocation, domain-proof handles, group chats,
the online custody mediator for time-boxed escrow, and the Laya monetization pipeline (Phase 7,
gated on consent + legal review). Everything deferred can be added without re-encrypting or
re-uploading anything already stored.

## Honest limits (from the doc, restated in the UI)

- Anyone who already decrypted and saved an image keeps it after unlink; the promise is "the
  network stops distributing it and no one new can open it," not "it never existed."
- A removed follower who cached the old audience key keeps access to old images until threshold
  custody is added.
- Chat history lives only in each device's local storage; there is no server copy for anyone —
  including the operator — to retrieve.
- With per-user escrow the operator *can* access one user's content under defined, logged
  circumstances. This network is not zero-knowledge, and the privacy policy must say so.
