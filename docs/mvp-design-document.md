# 67Social — MVP Design Document

Oct 6, 2026 · @Jose Tomas Guzman

67Social is an Instagram-style social network where images live encrypted across users' own phones and desktops instead of a central host, are viewable only by people holding the right key, and can be truly unlinked by the author. Feedback is reaction-only (5-emoji ratings, no text comments); following and messaging are request-gated; accepted message requests open a private chat that persists only in local storage. This document specifies the MVP.

## MVP scope

The MVP proves the full trust model end to end on two device types, with the smallest version of each subsystem. Everything that only matters at scale is deferred.

| Area | In the MVP | Deferred |
| --- | --- | --- |
| Device types | Phone (iOS + Android) and desktop node | Raspberry Pi / NAS / VPS node images |
| Storage | Encrypted chunks over iroh-blobs; 3-way replication | Reed-Solomon erasure coding; proof-of-storage repair loop |
| Ingest & quotas | Image-only validation, compress to a standard size, strip EXIF | Storage allowance tied to contributed nodes; add-node-or-unpublish gate |
| Access | One "Followers" audience key per user, delivered by HPKE | Custom circles (close friends, family); capability tokens; MLS |
| Unlink | Signed revocation + key destruction (crypto-shredding) | Threshold key custody for hard revocation |
| Identity | Root + per-device keys; shared identity directory over iroh-docs | Domain-proof handles; federated registrars |
| Feedback | Caption + 5-emoji reaction ratings (no text comments) | Custom emoji sets beyond the default palette |
| Social graph | Follow requests, message requests, ephemeral chat | Group chats; chat media sharing |
| Admin | Governance root (suspend, blocklist, handle registry); case-based escrow read | Online custody mediator for enforced time-boxing; threshold quorum |
| Discovery | Browse the identity directory; follow by handle | Hashtags; full-text search; recommendations |

The guiding rule: storage nodes are untrusted and only ever hold ciphertext, so every deferred item can be added later without re-encrypting or re-uploading anything already stored.

## Architecture

&#91;embedded content: 67Social architecture · clients, shared core, transport, operator\]

Every device runs the same shared Rust core; clients differ only in their front end. All protocols ride one Iroh transport over the peer network. The operator sits alongside: its governance key writes signed records into the directory, and escrow custody reads ciphertext through the transport as an authorized peer (dashed) only during a case.

## Technology stack and packaging

The core language is already fixed by the architecture: iroh is Rust, so the shared core is Rust and stays Rust — that is the one codebase that runs on every device. The open question is only the UI and packaging shell around it, and one constraint settles most of it.

**A SPA alone cannot run the core.** iroh needs raw UDP sockets, QUIC, and hole-punching — none of which a browser or WebView sandbox can do. So this is never a web app wrapped for the stores; it is always a native Rust core plus a web UI, running in one process and bridged. That rules out any "pure SPA in a WebView" approach, and rules out Node, Go, or C as the core.

**Recommended shell: Tauri 2.** [Tauri 2](https://v2.tauri.app/) ships one Rust core and one web-tech SPA to iOS, Android, and desktop from a single project. The Rust core runs natively in-process (so iroh gets its real UDP sockets), the UI renders in the OS WebView, and binaries stay small because no browser is bundled. Electron, by contrast, is desktop-only and ships a whole Chromium + Node runtime per app, so it cannot cover mobile and is heavier where it runs — keep it only as a desktop fallback, not the primary.

| Layer | Choice | Why / alternative |
| --- | --- | --- |
| P2P + crypto core | Rust — iroh, iroh-blobs, iroh-gossip, Laya tagging | Fixed by iroh; the same binary is also the headless node |
| App shell | Tauri 2 | One project → iOS + Android + desktop, Rust core in-process, small binaries. Alt: Capacitor (mobile) + Electron (desktop), more plumbing |
| UI (the SPA) | Svelte + TypeScript | No virtual DOM; compiles to minimal JS for light WebView bundles |
| Core ⇄ UI bridge | Tauri commands (Rust ⇄ JS) | Typed in-process calls, no network hop |
| Always-on node | The same Rust core as a headless daemon | Reuses the core; this is the durable storage node |

**Where each language fits.**

- Rust — the entire core: networking, encryption, storage, tagging glue. Non-negotiable.
- C — only behind FFI for a specific native library if ever needed; never a layer you write.
- Go — has libp2p, but iroh (Rust) is the chosen stack, so no role here.
- Node.js — appears only if you fall back to Electron (its runtime) or run a server-class node on iroh-js; not on mobile, not the core.

**Packaging per target.** On iOS and Android, Tauri 2 drives the Xcode and Gradle builds while the Rust core cross-compiles (cargo, plus the Android NDK) — the same CI set up in Phase 1. On desktop, Tauri produces native installers using the OS WebView (WebView2, WKWebView, WebKitGTK), with no Chromium to ship.

**Honest caveat.** Tauri 2's mobile targets are newer than its desktop ones and than Capacitor's mobile tooling, and not every plugin is as stable as the core; WebView behavior also differs across platforms. Fold a "does iroh run cleanly inside Tauri on a real phone" check into the Phase 0 spike before committing, so the shell choice is proven on device, not on paper.

## Identity and keys

Every capability in the system reduces to "who holds which key." There are five kinds, each with one job. No single key can both authenticate a user and read their content, which is what keeps the blast radius of any one leak small.

| Key | Held by | Purpose | On compromise |
| --- | --- | --- | --- |
| Root identity | The user (backed up offline) | The account's anchor; signs device keys and the user's directory record | Account recovery flow; worst case |
| Device key | Each phone / desktop | Signs posts and actions; is the Iroh endpoint's TLS identity | Revoke the one device, rotate affected audience keys |
| Audience key | All of a user's devices + audience members | Wraps per-post content keys so a circle can decrypt | Rotate the audience key; re-wrap existing post keys |
| Escrow key | Sealed, reconstructed per case | A second lock on every content key, for compliance access to one user | Scoped to one user; see the admin section |
| Admin / governance | The operator (you) | Signs suspensions, blocklists, handle bindings, app updates | Catastrophic for governance, but reads no content |

A user is a root keypair, ideally expressed as a DID. Each device generates its own key, signed by the root, so losing a phone never means losing the account: revoke that device key and rotate the audiences it could read. Audience keys are delivered to every one of a user's devices, so a post shared with you opens on both your phone and your laptop.

The root key never touches a storage node, and the admin key never wraps content by default. The escrow key is the one deliberate bridge between identity and content, and it is built so that it only ever unlocks one user at a time.

## Image storage, encryption, and unlink

Storage and access are separate problems: nodes store ciphertext freely, and a key decides who can read it. Because IPFS-style storage is built for permanence, deletion is built on encryption rather than erasure.

**Posting.** On the author's device:

1. Generate a random content key for the image.
2. Encrypt the full image and a small thumbnail separately with XChaCha20-Poly1305, so feeds load fast without fetching full images.
3. Chunk the ciphertext and hand it to iroh-blobs, which content-addresses it with BLAKE3. The hashes reveal nothing about the content, so no storage node learns anything.
4. Wrap the content key for the post's audience (see access control) and for the user's escrow key, and place the wrapped keys in the signed post record.

**Redundancy (MVP).** Each image is stored as 3 full replicas on nodes with different owners. Desktops carry most of this because they are online longer; phones seed their own new posts until a desktop picks them up, then fetch opportunistically. Erasure coding and an automatic repair loop replace plain replication post-MVP.

**Unlink (crypto-shredding).** To unlink a post, the author publishes a signed revocation over iroh-gossip and destroys the content key. Nodes drop the chunks at the next garbage-collection pass and stop replicating them, so the ciphertext decays instead of being maintained. The honest limit, which belongs in the product copy: anyone who already decrypted and saved the image keeps their copy. The promise is "the network stops distributing it and no one new can open it," not "it never existed." Hard revocation (keys fetched at view time from threshold custodians) is the post-MVP upgrade that closes the cached-key gap.

BLAKE3 hashes are not IPFS CIDs, so the network is not interoperable with public IPFS. For a private social network that is acceptable, and arguably a feature.

## Ingest and storage contribution

The front end does two jobs before an image becomes a blob: it guarantees that what gets stored is a bounded, safe image, and it ties how much a user can store to how much storage they contribute — which is what keeps the network free of server costs.

**Ingest guarantees (MVP, in the posting pipeline).**

- Validate it is really an image by decoding it, not by trusting the file extension or MIME type; reject anything that fails to decode. This also blocks malformed files aimed at exploiting decoders downstream.
- Strip EXIF and other metadata, GPS location included, so the photo carries no hidden location or device data into storage.
- Re-encode and compress to a standard ceiling — e.g. max 2048 px on the long edge, WebP/AVIF at a target quality — plus the small thumbnail. This bounds per-image bytes and normalizes what every node stores.

Only the normalized image is then encrypted, chunked, and handed to iroh-blobs; the original never leaves the device.

**Storage contribution (next phase).** Storage is the one real cost in a server-free network, so users pay it in kind. Each account has an allowance = a small base (phone-only) + whatever durable storage the user's own desktop nodes verifiably contribute. On reaching the allowance, posting is blocked with a clear choice: add a desktop node (which raises the allowance in proportion to what it hosts for others) or unpublish older images to free space. This is friend-to-friend reciprocity — you earn room by hosting for others — and it keeps the system free with no money changing hands.

**Mechanics and honest limits.**

- The allowance is counted in published bytes, not image count, so the compression step directly stretches how far the base goes.
- Contribution is measured by the repair / health system — how much verified storage a user's nodes actually serve — so the gate lands naturally alongside erasure coding and the proof-of-storage repair loop, in the same phase.
- Enforcement in a P2P network is ultimately social: a modified client could ignore the gate. The defense is to tie any meaningful allowance to *verifiable* contribution (proof-of-storage spot checks), so cheating costs more effort than it saves rather than relying on the client to behave.

Phasing: the ingest guarantees belong in Phase 2 (post and view); the contribution gate lands in Phase 3, with the erasure coding and repair loop that measure contribution.

## Access control

Encrypting each content key separately for every follower works for 20 people, not 2,000. The MVP uses one audience key per user, the "Followers" circle, with the data model built so custom circles slot in later.

**Delivery.** When someone is accepted as a follower, the author's device delivers the current Followers audience key to the new follower, encrypted to their public key with HPKE (the standard "encrypt to a public key" construction). This happens once. After that, the follower can open every post shared with that circle with no per-post key exchange.

**Viewing a post.** A follower's device receives the post record over gossip, unwraps the content key with the audience key it already holds, fetches the chunks from whichever nodes have them, decrypts, and displays. Public posts are the simple case: the content key sits in the record unwrapped, so anyone can view.

**Removal and rotation.** When a user removes a follower, the audience key is rotated: a new version is generated and delivered to everyone except the removed person, and new posts use it. For older posts, only their small wrapped content keys are re-wrapped with the new key and re-gossiped. The images never move or re-encrypt, which matters when storage is spread across phones. As with unlink, a removed follower who cached the old key and ciphertext keeps access to those old images until threshold custody is added.

**Defense in depth (post-MVP).** Because Iroh connections are authenticated by public key, a node always knows who is asking. Later, authors can issue signed capability tokens ("this key may fetch audience X's chunks until date D") that nodes check before serving. This adds no confidentiality over the encryption, but it curbs bulk harvesting of ciphertext and metadata.

## Posts, captions, and reactions

A post is a signed record authored on a device: the encrypted image reference, an optional caption, the audience, wrapped content keys, and a timestamp. The caption is plaintext inside the record for public posts and encrypted alongside the image for private audiences, so it is as protected as the photo it describes.

**Reactions replace comments.** There is no free-text comment section. Feedback is a rating across several emoji scales, each from 1 to 5. The default palette is three scales: stars (quality), hearts (affection), and one more expressive emoji; a viewer can rate on any subset. This keeps interaction expressive but bounded, removes the main moderation and abuse surface of a photo network (text), and makes feedback a small, structured value instead of a thread.

Each reaction is its own tiny signed record: `{ post, rater, scale, value (1–5), timestamp }`, gossiped to the post's audience. The author's device aggregates them into an average and a count per scale ("4.2★ from 31, 4.8❤ from 27"). A rater can change or withdraw a rating by signing a newer record for the same scale; last-writer-wins by timestamp.

**Privacy of ratings.** Ratings inherit the post's audience: a rating on a private post is encrypted to that audience, so only its members and the author see who rated what. Aggregates shown to the author never need to reveal individual raters unless you choose to.

**Why this shape fits the architecture.** Reactions are small, append-only, and signed, so they sync over the same gossip layer as posts with no central tally server. Removing an abusive rater is the same operation as removing a follower: rotate the audience key, and their future reactions no longer decrypt.

## Social graph

Nothing connects two users without consent. A follow request and a message request are separate gates with different payoffs on acceptance, and declining either leaves no durable record.

&#91;embedded content: follow and message request flows · 2 lanes, 1 decision each\]

Accepting a follow delivers the "Followers" audience key (the new follower can now decrypt posts). Accepting a message request opens a direct, authenticated Iroh stream whose history lives only in each device's `localStorage` — no node ever stores it. A declined follow can be re-requested; a declined message request is simply dropped, and blocking prevents re-request.

## Ephemeral private chat

An accepted message request opens a one-to-one chat that is deliberately not durable. There is no chat history stored on any node and none synced between a user's own devices. The only persistence is each participant's own `localStorage` on the device where the conversation happened.

**Transport.** Messages travel over a direct, authenticated Iroh connection between the two devices' endpoints, end-to-end encrypted by QUIC. When both are online, messages flow directly; the relay only ever sees ciphertext if hole-punching fails. Nothing is written to iroh-blobs, iroh-docs, or the gossip log, so there is no network copy to subpoena, leak, or repair.

**Persistence model.** Each client keeps the running conversation in memory and mirrors it to `localStorage` so it survives an app reload on that device. Consequences, which should be stated plainly in the UI:

- Clearing the app's storage, or opening the chat on a different device, shows an empty conversation.
- A message sent while the other person is offline is held by the sender's device and delivered on reconnect; if the sender never reconnects while the recipient is online, it is not delivered. (A short store-and-forward window via the participants' own nodes is a possible post-MVP softening.)
- Because there is no server copy, neither the operator nor the escrow mechanism can retrieve chat contents. This is a genuine limit on the admin capability and should be documented as such.

**Lifecycle.** Either party can end the chat, which signals the other device to drop its `localStorage` copy. Blocking a user tears down the connection and prevents re-request.

This gives "request → accept → talk → gone" semantics with no infrastructure to hold conversations, at the cost of cross-device history, which is the intended trade.

## Admin and compliance

The operator has two separate powers, and keeping them separate is the whole design. Most administration needs no ability to decrypt anything.

**Governance (no content access).** The admin key is the root of governance. It signs records that every client enforces automatically because they are verifiable signatures in the shared directory: account suspension and device-key revocation, content-hash blocklists for illegal material, handle-to-key bindings (the registrar that breaks @handle ties), and app / protocol updates. This is real control that never touches a photo.

**Case-based content access (per-user, silent, bounded).** Every user has their own escrow keypair. Each content key the user produces is wrapped to that escrow public key as a second lock, so opening a case on one user unlocks only that user's content and affects no one else. There is no global master key. To navigate a user's content, the admin tool walks their signed post log, fetches ciphertext like any authorized reader, and unwraps offline with the per-user escrow key.

Two honest limits to design around:

1. **Time-boxing needs a mediator.** Pure crypto scopes access to one user but cannot expire a key you already hold. Genuine "case open for 14 days" enforcement requires a small online custody service / HSM that holds the escrow shares and performs each unwrap on request, so it can refuse after expiry and log every call. Without it you get per-user scoping but not real temporal limits. Build the mediator if "temporal" must be enforced rather than promised.
2. **Unlink vs. escrow collide.** If an unlinked post's escrow key is destroyed with its content key, the operator can no longer read it; if it is retained, unlink is not absolute. The compliance-friendly middle ground: retain the escrow-wrapped key for a fixed window (e.g. 30–90 days) after unlink, then destroy it. Pick the window deliberately and put it in the retention policy.

**Silence vs. disclosure — keep these distinct.** Not notifying the subject of an active case is normal and fine; no event is emitted to the user, and nodes see only an ordinary blob request. Never telling users the capability exists at all is the legal risk. The privacy policy must disclose that operator access can occur for safety and legal compliance, even though individual cases stay silent. Chile's Ley 21.719 (new data-protection law, taking effect around end of 2026) and GDPR-style regimes require disclosing who can access personal data and under what circumstances. This is lawyer-review territory before launch.

**Accountability is armor, not notification.** Because the power is silent and strong, safeguard it internally: require a quorum to open a case (e.g. 2-of-3 officers holding escrow shares via threshold crypto, on offline hardware keys), and write every access to an append-only, signed audit log (who, which user, when, case reference) whose hash is published periodically so it cannot be rewritten. The day the use is questioned, that log is what exonerates it.

**Product-claim consequence.** With per-user escrow the operator demonstrably *can* access content, so the network cannot be marketed as zero-knowledge or "we can't see your photos." The accurate claim is "private between you and your audience; the operator can access content under defined, logged circumstances" — the iCloud-style model, not the Signal-style one.

## Core data model

Every record is signed by its author's device key and verifiable by any node without trusting whoever relayed it. Three transport layers carry them: the identity directory (iroh-docs, replicated), the gossip log (pub/sub to an audience), and iroh-blobs (content-addressed ciphertext).

| Record | Lives in | Encrypted? | Notes |
| --- | --- | --- | --- |
| User directory entry | Identity directory | No (public-safe) | Root key, device keys, handle, display name, avatar hash, serving nodes. Nothing private — no follower lists |
| Image blob | iroh-blobs | Yes (per-image key) | Full image + thumbnail as separate encrypted chunks; 3 replicas |
| Post record | Gossip log | Caption + keys wrapped to audience | Blob ref, caption, audience id, content key wrapped to audience and to escrow, timestamp |
| Reaction | Gossip log | Inherits post's audience | `{ post, rater, scale, value 1–5, timestamp }`; last-writer-wins per scale |
| Audience key delivery | Direct (HPKE) | Yes (to recipient's pubkey) | One-time handoff when a follow is accepted |
| Revocation (unlink) | Gossip log | No (signed) | Signed "drop blob X"; triggers chunk GC and key destruction |
| Follow / message request | Direct, then gossip | Signed | Pending → accepted / declined; acceptance triggers key delivery or chat setup |
| Chat message | Direct Iroh stream | Yes (QUIC) | Never stored on any node; `localStorage` only on each device |
| Governance record | Identity directory | No (signed by admin) | Suspension, blocklist entry, handle binding, update manifest |
| Audit-log entry | Operator's append-only log | Signed | Case access events; periodic hash published |

The design invariant: a storage node can hold every blob and still learn nothing but sizes and timestamps, and the public directory can be fully browsed without exposing anyone's social graph or private content.

## Monetization: privacy-preserving marketing signals

The monetization layer sells aggregate, anonymized marketing insights derived from photos — never individual profiles, and never the photos themselves. It works only because classification happens entirely on-device: the image stays encrypted and local, and only coarse, consented, de-identified signals ever leave.

**What Laya is, and what it is not.** [Laya](https://laya.convaiinnovations.com/) is an on-device, non-autoregressive decision engine (Apache-2.0, \~33 ms, 100+ languages) that evaluates typed questions — choice, score, boolean — over *text* in a single forward pass, returning calibrated probabilities and never free text, so it cannot hallucinate or emit an off-schema tag. That fits the goal of local, controlled tagging well, but it classifies text, not pixels: a photo must first be turned into text, so the pipeline needs a vision step in front of Laya.

**On-device pipeline (next phase).**

1. At ingest — after compression, before encryption — an on-device vision labeler (platform labelers, or a small open CLIP via the Rust core) produces candidate labels from the photo.
2. Laya scores those labels plus the user's caption against a fixed marketing taxonomy: choice (product category, ≤20 options or a coarse-to-fine hierarchy, since Laya degrades past \~20 options), score (e.g. purchase-intent 0–3), boolean (e.g. "outdoor scene"). Calibrated confidence lets you keep only tags above a threshold and drop the rest.
3. The kept tags are reduced to a coarse, schema-bounded bucket and queued for anonymized, batched emission.
4. Nothing about the image, the raw labels, or the user's identity leaves the device — only the final de-identified bucket.

**Making "anonymous" actually hold.** This is the hard part, and attaching device info works against it, so handle it with care:

- No identifiers. The emitted record carries no account key, device id, or anything joinable back to the user's directory record or posts; the marketing pipeline must be structurally unable to link a tag to a 67Social user.
- Device info, coarse only. At most non-unique buckets (OS family, app version, country/region, optional self-declared age band). A full device fingerprint is a quasi-identifier and would de-anonymize the record — avoid it.
- k-anonymity and aggregation. A bucket is reportable only once at least k users share it; rare combinations are suppressed. Local differential privacy (randomized response) is worth considering so even the collection point trusts only the aggregate, never a single record.
- Timing decorrelation. Batch and jitter emission so a record cannot be correlated with a specific upload.
- No sensitive inferences. The taxonomy is designed to exclude special-category signals (health, religion, ethnicity, politics, sexual orientation); Laya's fixed schema makes this enforceable, since it answers only the questions you define.

**What you can sell.** Aggregate audience insights — "this month, N% of posts in region R carried outdoor or fitness themes" — not per-user profiles or ad targeting. With no central ad server and content encrypted, per-user targeting is impossible anyway, so aggregate trend data is both the natural and the defensible product.

**Consent and legal — the gate on all of this.** Deriving marketing data from people's photos is processing personal data, and photos can reveal special-category data, so it must be strictly opt-in (default off), explained in plain language, and revocable at any time; revocation stops emission (already-aggregated, privacy-safe data cannot be recalled, which is why the aggregates must be safe from the start). Ley 21.719 and GDPR-style regimes require a lawful basis, purpose limitation, and heightened protection for special-category data. Quietly turning a privacy-first network's photos into marketing data would be both unlawful and reputationally fatal — counsel review before building, not after.

**Footprint note.** Laya's checkpoints are \~320–420M params (\~650–810 MB download). On mobile that is a real one-time footprint, running on the NPU/CPU at ingest; validate on-device size and latency budgets before committing, and consider a smaller distilled taxonomy model if needed.

Phasing: this reuses the Phase 2 ingest hook and ideally the Phase 3 health system, but lands as a distinct later phase, gated on the consent and legal work above.

### Example marketing taxonomy

These signals are illustrative only — the real set is a tuning exercise. What matters structurally is that the taxonomy is centrally administered and applied at ingest, before encryption, so it never breaks the downstream flow.

| Signal | Laya type | Example values / rubric | Marketing use |
| --- | --- | --- | --- |
| Scene context | choice | outdoor-nature, urban, home, restaurant, travel, event, fitness, retail | Where audiences spend time; placement context |
| Product category | choice | none, fashion, beauty, food & beverage, electronics, home, auto, sports, pets | Category demand signals (coarse; fine-tune as a hierarchy) |
| Brand/logo present | boolean | P(a recognizable logo is visible) | Brand-affinity and sponsorship trends |
| Promotional vs personal | boolean | P(product showcase / sponsored-style, not a personal snapshot) | Separate organic from commercial content |
| Lifestyle theme | choice | minimalist, luxury, adventure, cozy, wellness, foodie, tech, vintage | Aesthetic audience segmentation |
| Aspirational intent | score | 0 none → 3 strong, catalog-like / shoppable | Purchase-propensity proxy |
| Production quality | score | 0 casual snapshot → 3 professional / studio | Creator-tier / influencer signal |

Each signal stays within Laya's constraints: choice schemas under \~20 options (split into a coarse-to-fine hierarchy if a category needs more), scores as a short ordinal rubric, booleans as a single calibrated probability. None infers a special category (health, religion, ethnicity, politics, sexual orientation), and none identifies a person.

In Laya's own schema form, a few of these look like:

```json
{
  "scene": {
    "type": "choice",
    "instructions": "Primary setting of the photo",
    "criteria": {
      "outdoor_nature": "parks, mountains, beach, countryside",
      "urban": "streets, city, architecture",
      "home": "indoor domestic spaces",
      "restaurant": "cafes, bars, dining",
      "travel": "landmarks, airports, hotels",
      "fitness": "gym, sports, running, yoga",
      "retail": "stores, malls, shopping"
    }
  },
  "aspirational_intent": {
    "type": "score",
    "instructions": "How shoppable / catalog-like is the image?",
    "criteria": ["none", "mild", "clear", "strong"]
  },
  "promotional": {
    "type": "noul",
    "instructions": "Is this a product showcase or sponsored-style post rather than a personal snapshot?"
  }
}
```

**Central administration.** The taxonomy is a signed, versioned manifest published by the governance key — the same admin channel as blocklists and handle bindings — which every client fetches and pins. It is applied at ingest, before encryption, because that is the only moment the plaintext image is available on-device; once encrypted, the content is opaque and nothing downstream can re-derive tags. Updates are forward-only: a new taxonomy version changes only future uploads and never requires re-encrypting or re-tagging stored images. Each emitted bucket reports the taxonomy version it used, so aggregates stay comparable across versions, and central control lets you keep the schema within consent and legal bounds — and adjust it to marketing needs — without shipping an app update.

## Build phases

Each phase is independently demonstrable, and every phase stores only ciphertext, so later phases never force re-encryption or re-upload of earlier data. Build the shared Rust core once; the desktop node and the mobile app are the same core with different front ends (headless daemon vs. native UI), so a working server node and the app fall out of one codebase.

| Phase | Goal | Delivers | Proves |
| --- | --- | --- | --- |
| 0 — Spike | Validate the stack | Two phones + one Linux node exchange one encrypted image via iroh-blobs and a revocation via iroh-gossip | Iroh FFI, encryption, unlink work on device |
| 1 — Core + identity | Shared Rust core, keys, directory | Root/device keys, iroh-docs identity directory, QR pairing | Identity and discovery on phone + desktop |
| 2 — Post and view | The feed | Encrypt → chunk → store (3 replicas) → gossip → fetch → decrypt; captions | End-to-end private posting |
| 3 — Access + unlink | Audiences and erasure | Followers audience key via HPKE, rotation on removal, signed unlink | The core trust model |
| 4 — Reactions | Replace comments | 5-emoji rating records, aggregation, change/withdraw | Bounded feedback over gossip |
| 5 — Social graph | Requests and chat | Follow requests, message requests, ephemeral `localStorage` chat | Gated connection + disappearing chat |
| 6 — Admin | Governance + compliance | Admin-signed suspend/blocklist/handles; per-user escrow read with audit log | Operable, compliant network |
| 7 — Monetization | Anonymized marketing signals | On-device Laya tagging over a fixed taxonomy; k-anonymous, consented, aggregate-only emission | Revenue without per-user tracking |

**Critical path for an early demo:** Phases 0 → 1 → 2 give a working "post a private photo, see it on another device" story. Phase 3 is where it becomes trustworthy. Reactions, social graph, and admin (4–6) can proceed in parallel once the core in 1–3 is stable.

**Tooling note:** set up Rust cross-compilation CI early. Android in particular needs the `.so` libraries built with cargo-ndk on Linux/macOS, and getting that into the pipeline before Phase 1 avoids a recurring tax.

## Open questions and risks

**Phones are poor storage nodes.** iOS and Android suspend background processes, so a phone stops serving the moment the app closes. The MVP treats phones as opportunistic seeders and leans on desktops for durable storage; whether 3-way replication across mostly-desktop nodes gives acceptable availability is the first thing to measure in Phase 2.

**FFI surface may be thin.** iroh-ffi mirrors the core connection API, but iroh-blobs / gossip / docs may not be exposed in Swift and Kotlin. The plan assumes a custom UniFFI wrapper around the Rust core; confirm which protocols cross the FFI boundary before committing Phase 1 estimates.

**Cached-key leakage is inherent.** Both unlink and follower-removal leave a window where someone who already pulled the key and ciphertext retains access. The MVP accepts this and discloses it; threshold key custody is the real fix and should be scheduled, not just listed.

**Moderation on an encrypted network.** Illegal-content handling relies on content-hash blocklists plus report-with-attached-key review. This covers public and reported content but not unreported private content, which regulators may find insufficient. Needs a written policy and legal review.

**Legal disclosure of operator access.** The escrow capability must be disclosed (Ley 21.719, GDPR-style regimes) even while individual cases stay silent. Draft the privacy-policy language and have counsel review before any public launch.

**Handle-squatting and Sybil accounts.** The admin registrar breaks handle ties but does not stop mass account creation. Consider a lightweight proof-of-personhood or invitation model before opening registration.

**Spam reactions.** Bounded 1–5 ratings remove text abuse but not vote-stuffing from fake followers. Audience-gated reactions limit this to accepted followers; watch whether that is enough.

**Open decisions to make before Phase 1:** the default third emoji scale beyond stars and hearts; the exact unlink-retention window for escrow (30 vs. 90 days); whether to ship the time-boxing mediator in the MVP or document escrow as non-expiring for now.
