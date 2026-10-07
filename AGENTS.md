# AGENTS.md — 67Social

## What this is

MVP implementation of `docs/mvp-design-document.md` (both files in `docs/` are the same document).
A P2P encrypted social network: one shared Rust core (`crates/core`), a headless node daemon
(`crates/node`), and a Tauri 2 + Svelte app (`app/`). Storage nodes hold only ciphertext.

## Non-negotiable invariants (from the design doc — do not break these)

1. **Nodes never see plaintext.** Everything in iroh-blobs is XChaCha20-Poly1305 ciphertext under a
   per-post content key. Hashes are BLAKE3 of ciphertext.
2. **No single key authenticates a user AND reads their content.** Root signs devices; device signs
   posts; audience key (symmetric) wraps content keys; escrow key is per-user only.
3. **Chat is ephemeral and device-local.** Never write chat to the record log, iroh-blobs, gossip,
   or the store module. The UI mirrors to `localStorage` only (see `app/src/lib/api.ts`).
4. **Every record is signed and verified on apply** (`feed.rs` `apply`); idempotent; last-writer-wins
   by timestamp for reactions; only the post author may revoke.
5. **Gossip has no history** — `Session::rebroadcast_mine` re-gossips self-authored records on an
   interval so late joiners converge. Keep this when changing sync logic.
6. **The original image never leaves the device** — ingest (decode-validate, strip EXIF, resize)
   runs before encryption, always (`ingest.rs`).

## Build / test

```bash
cargo test -p social67-core      # unit tests + e2e.rs (real iroh transport, ~8s)
cargo check --workspace          # everything compiles
cd app && pnpm build             # UI bundle
pnpm tauri build --bundles deb   # app binary + .deb installer
```

`SOCIAL67_DATA_DIR` env var overrides the app data dir (use it to run two app instances locally).
`SOCIAL67_GC_SECS` sets the GC interval (default 15; e2e tests set 2).

## Admin / GC mechanics (easy to break)

- **Blob GC**: every blob added via `Node::add_blob` gets a named tag (hex of its hash). On unlink,
  `Session::apply_record` sends those hashes to the tag-drop task; the iroh-blobs GC (interval
  `SOCIAL67_GC_SECS`) sweeps untagged blobs not in the `KeepSet`. `KeepSet` is recomputed from the
  feed after every applied record. If you change this: a blob tagged forever = unlink broken.
- **Node::Drop** signals the store actor to shut down (releases the redb lock) and sets the task
  stop flag. Without it, a dropped session keeps the DB locked and the next `Session::start` on the
  same dir hangs. Any new spawned task holding a store clone must honor `_stop`/StopFlag.
- **Gossip has no history, and processes exit**: the admin CLI pumps ~20s after publishing so the
  record survives its own exit (queued broadcasts die with the endpoint).
- **admin.pub** contains *public* keys (one per line). admin.json contains the *private* seed —
  never write one into the other.

## Version pins that matter

- iroh 1.3 + iroh-blobs 0.103.1 + iroh-gossip 0.101 — verified API pairing (0.103.0 was yanked).
- x25519-dalek 2 needs `getrandom` and `static_secrets`; its `random_from_rng` is pinned to
  rand_core 0.6, so use `::random()` constructors, not rand 0.9 RNGs (see `crypto.rs`).
- serde does not implement traits for `[u8; 64]` — signatures are `Vec<u8>` in serialized structs.
- JSON map keys must be strings — `StoredFeed.audience_keys` is a `Vec<(PubKey, SymKey)>`.

## Conventions

- Rust 2021, `anyhow` in app layers, `thiserror` in library modules, postcard for wire
  serialization, serde_json for persistence and the UI bridge.
- Tauri commands return `Result<T, String>`; the UI polls `get_state` / `drain_events` every ~1.5s.
- Records addressed to a root carry an explicit `author`/`from` field so receivers can verify the
  device-certificate chain against the right root key.

## If you change these, update the docs

- Record shapes (`records.rs`) → core data model table in `docs/mvp-design-document.md`.
- Key kinds or trust boundaries → the identity/keys and admin sections.
- Anything touching chat persistence → the ephemeral chat section.
