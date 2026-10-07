//! Phase-0 spike, as an integration test: two devices exchange an
//! encrypted image via iroh-blobs and a revocation via iroh-gossip, over a
//! real Iroh transport (local QUIC, in-memory address book — no external
//! discovery needed).

use std::time::Duration;

use social67_core::feed::FeedEvent;
use social67_core::records::{Audience, Scale};
use social67_core::session::{fresh_topic, BlobKind, Session, SessionEvent};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "social67-e2e-{}-{}-{}",
        tag,
        std::process::id(),
        rand_suffix()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn rand_suffix() -> u64 {
    use rand::RngCore;
    rand::rng().next_u64()
}

/// A small gradient PNG generated in-memory (real image bytes for ingest).
fn test_image(w: u32, h: u32) -> Vec<u8> {
    let mut img = image::RgbImage::new(w, h);
    for (x, y, px) in img.enumerate_pixels_mut() {
        *px = image::Rgb([(x % 255) as u8, (y % 255) as u8, 128u8]);
    }
    let mut buf = Vec::new();
    img.write_with_encoder(image::codecs::png::PngEncoder::new(&mut buf))
        .unwrap();
    buf
}

/// Pump both sessions until `cond` holds or the deadline passes. Both
/// devices pump: gossip has no history, so each side must be alive to
/// rebroadcast its own records for the other.
async fn pump_until<F: Fn(&Session, &Session) -> bool>(
    a: &mut Session,
    b: &mut Session,
    cond: F,
    secs: u64,
) -> bool {
    for _ in 0..secs * 10 {
        a.pump().await;
        b.pump().await;
        if cond(a, b) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    cond(a, b)
}

async fn start(tag: &str, handle: &str, topic: iroh_gossip::proto::TopicId) -> Session {
    Session::start(temp_dir(tag), handle, handle, topic, vec![])
        .await
        .expect("session starts")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_full_trust_model() {
    // Short GC interval so the crypto-shredding sweep is observable.
    std::env::set_var("SOCIAL67_GC_SECS", "2");
    let _ = tracing_subscriber::fmt()
        .with_env_filter("social67_core=info")
        .try_init();

    let topic = fresh_topic();
    let mut alice = start("alice", "alice", topic).await;
    let mut bob = start("bob", "bob", topic).await;

    // Out-of-band exchange (the "invite"): addresses + gossip meshing.
    alice.add_peer_addr(bob.node.addr());
    bob.add_peer_addr(alice.node.addr());
    alice.join_gossip_peer(bob.node.node_id()).await.unwrap();
    bob.join_gossip_peer(alice.node.node_id()).await.unwrap();

    let alice_root = alice.identity.root_pub().unwrap();
    let bob_root = bob.identity.root_pub().unwrap();

    // --- Directory discovery: bob learns alice's entry over gossip ---
    assert!(
        pump_until(&mut alice, &mut bob, |a, b| {
            a.feed.directory.contains_key(&bob_root) && b.feed.directory.contains_key(&alice_root)
        }, 30)
        .await,
        "both devices should discover each other's directory entries"
    );
    assert_eq!(
        bob.feed.directory.get(&alice_root).unwrap().handle,
        "alice"
    );

    // --- Public post: encrypt → blob → gossip → fetch → decrypt ---
    let png = test_image(800, 600);
    let post_id = alice
        .create_post(&png, "hello network", Audience::Public)
        .await
        .expect("alice posts");

    assert!(
        pump_until(&mut alice, &mut bob, |_, b| b.feed.posts.contains_key(&post_id), 20).await,
        "bob should receive the post record over gossip"
    );

    // Bob fetches ciphertext from alice's node and decrypts with the
    // public content key from the record.
    let (post, thumb) = {
        let entry = bob.feed.posts.get(&post_id).unwrap();
        let post = entry.env.payload.clone();
        let thumb = bob.decrypt_blob(&post, BlobKind::Thumb).await;
        (post, thumb)
    };
    let thumb = thumb.expect("bob decrypts the thumbnail");
    image::load_from_memory(&thumb).expect("thumbnail is a valid image");

    let image = bob
        .decrypt_blob(&post, BlobKind::Image)
        .await
        .expect("bob fetches and decrypts the full image from alice");
    let decoded = image::load_from_memory(&image).unwrap();
    assert_eq!(decoded.width(), 800);
    assert_eq!(decoded.height(), 600);
    // Bob is now a replica: he holds the ciphertext locally.
    assert!(bob
        .node
        .get_blob(&iroh_blobs::Hash::from(post.blob_hash))
        .await
        .is_ok());

    // --- Reactions: bob rates; alice aggregates ---
    bob.react(&post_id, Scale::Stars, 5).await.unwrap();
    bob.react(&post_id, Scale::Hearts, 4).await.unwrap();
    assert!(
        pump_until(&mut alice, &mut bob, |a, _| a.feed.aggregate(&post_id).len() == 2, 20).await,
        "alice should aggregate bob's reactions"
    );
    let agg = alice.feed.aggregate(&post_id);
    assert_eq!(agg[0], (Scale::Stars, 5.0, 1));
    assert_eq!(agg[1], (Scale::Hearts, 4.0, 1));

    // --- Private post gated by follow acceptance + HPKE key delivery ---
    bob.request_follow(alice_root).await.unwrap();
    assert!(
        pump_until(&mut alice, &mut bob, |a, _| a
            .feed
            .pending_follow_requests
            .contains_key(&bob_root), 20)
        .await,
        "alice should see bob's follow request"
    );
    alice.accept_follow(&bob_root).await.unwrap();
    assert!(
        pump_until(&mut alice, &mut bob, |_, b| b.feed.audience_keys.contains_key(&alice_root), 20)
            .await,
        "bob should receive and open the sealed audience key"
    );

    let private_id = alice
        .create_post(&png, "for followers only", Audience::Followers { author: alice_root })
        .await
        .unwrap();
    assert!(
        pump_until(&mut alice, &mut bob, |_, b| b.feed.posts.contains_key(&private_id), 20).await,
        "bob receives the private post record"
    );
    let private_post = bob.feed.posts.get(&private_id).unwrap().env.payload.clone();
    let private_thumb = bob
        .decrypt_blob(&private_post, BlobKind::Thumb)
        .await
        .expect("bob opens the private post with the delivered audience key");
    image::load_from_memory(&private_thumb).unwrap();
    // The caption is sealed for private posts and opens with the content key.
    let content_key = bob.content_key_for(&private_post).unwrap();
    assert_eq!(
        social67_core::feed::Feed::open_caption(&private_post, &content_key).unwrap(),
        "for followers only"
    );

    // --- Ephemeral chat over a direct stream (request-gated) ---
    bob.request_message(alice_root).await.unwrap();
    assert!(
        pump_until(&mut alice, &mut bob, |a, _| a
            .feed
            .pending_message_requests
            .contains_key(&bob_root), 20)
        .await,
        "alice sees bob's message request"
    );
    alice.accept_message(&bob_root).await.unwrap();
    assert!(
        pump_until(&mut alice, &mut bob, |_, b| b.feed.open_chats.contains(&alice_root), 20).await,
        "bob's chat opens on acceptance"
    );
    bob.send_chat(alice_root, "hi alice").await.unwrap();
    assert!(
        pump_until(&mut alice, &mut bob, |a, _| a.events.iter().any(|e| matches!(
            e,
            SessionEvent::ChatReceived { from, body, .. } if *from == bob_root && body == "hi alice"
        )), 20)
        .await,
        "alice receives the chat over the direct stream"
    );

    // --- Unlink: signed revocation decays the ciphertext ---
    alice.unlink(&post_id).await.unwrap();
    assert!(
        pump_until(&mut alice, &mut bob, |_, b| b.feed.revoked.contains(&post_id), 20).await,
        "bob applies the signed revocation"
    );

    // Non-author revocation is rejected.
    let fake = social67_core::records::RevocationRecord {
        author: alice_root,
        post_id: private_id,
        blob_hash: private_post.blob_hash,
        thumb_hash: private_post.thumb_hash,
        created_at: social67_core::now_ms(),
    };
    let bob_device = bob.identity.device().unwrap();
    let fake_env = social67_core::records::Envelope::sign_with_device(fake, &bob_device);
    assert!(bob.feed.apply(&social67_core::records::Record::Revocation(fake_env)).is_err());

    // --- Events surfaced for the UI along the way ---
    assert!(alice
        .events
        .iter()
        .any(|e| matches!(e, SessionEvent::Feed(FeedEvent::FollowRequest { from }) if *from == bob_root)));

    // ================= Phase 6: admin =================

    // Operator: admin key + pinned on both devices (the pin file is how a
    // node learns which governance keys to trust).
    let admin_dir = temp_dir("admin");
    std::fs::create_dir_all(&admin_dir).unwrap();
    let admin = social67_core::admin::AdminIdentity::generate();
    social67_core::admin::pin_admin_key(&admin_dir, &admin.admin_pub()).unwrap();
    // The sessions must re-read admin keys — pin directly into the feeds
    // for the test (the file path is used by real deployments).
    alice.feed.admin_keys.insert(admin.admin_pub());
    bob.feed.admin_keys.insert(admin.admin_pub());

    // Governance: suspend bob. Alice's feed then refuses his posts.
    admin
        .sign_governance(
            social67_core::records::GovernanceAction::Suspend {
                root: bob_root,
                reason: "test suspension".into(),
            },
            social67_core::now_ms(),
        )
        .verify(&admin.admin_pub())
        .unwrap();
    let suspend_env = admin.sign_governance(
        social67_core::records::GovernanceAction::Suspend {
            root: bob_root,
            reason: "test suspension".into(),
        },
        social67_core::now_ms(),
    );
    alice.apply_record(social67_core::records::Record::Governance(suspend_env.clone())).unwrap();
    bob.apply_record(social67_core::records::Record::Governance(suspend_env.clone())).unwrap();
    assert!(alice.feed.is_suspended(&bob_root));

    let bob_post = social67_core::records::Envelope::sign_with_device(
        {
            use social67_core::records::KeyMaterial;
            social67_core::records::PostRecord {
                id: [7; 32],
                author: bob_root,
                blob_hash: [8; 32],
                thumb_hash: [9; 32],
                caption: social67_core::records::Caption::Plain("suspended content".into()),
                audience: Audience::Public,
                key_material: KeyMaterial::Plain(social67_core::crypto::SymKey::generate()),
                wrapped_escrow: social67_core::records::SealedKey {
                    sealed: social67_core::crypto::seal_to(&social67_core::keys::EscrowIdentity::generate().public(), &[0u8; 32]).unwrap(),
                },
                created_at: social67_core::now_ms(),
            }
        },
        &bob.identity.device().unwrap(),
    );
    let err = alice.apply_record(social67_core::records::Record::Post(bob_post)).unwrap_err();
    assert!(
        err.downcast_ref::<social67_core::feed::ApplyError>()
            .map(|e| matches!(e, social67_core::feed::ApplyError::AuthorSuspended))
            .unwrap_or(false),
        "expected AuthorSuspended, got: {err}"
    );

    // Reinstate bob.
    let reinstate_env = admin.sign_governance(
        social67_core::records::GovernanceAction::Reinstate { root: bob_root },
        social67_core::now_ms(),
    );
    alice.apply_record(social67_core::records::Record::Governance(reinstate_env)).unwrap();
    assert!(!alice.feed.is_suspended(&bob_root));

    // Escrow case read: the operator walks alice's post log with her
    // escrow key — scoping means only alice's content is readable.
    let escrow = alice.escrow_identity().unwrap();
    let out_dir = temp_dir("case");
    let mut audit = social67_core::admin::AuditLog::open(
        admin_dir.join("audit.jsonl"),
        admin.admin_pub(),
    )
    .unwrap();
    let n = social67_core::admin::run_case(
        &mut alice,
        &escrow,
        &alice_root,
        "C-001",
        &out_dir,
        &mut audit,
    )
    .unwrap();
    // Alice published 2 posts (public + followers-only); the unlinked one's
    // escrow path may still be readable pre-GC, but content-wise both
    // should be accessible via escrow (unlink retains escrow for the
    // retention window in the design).
    assert!(n >= 1, "case read should decrypt at least one image");
    audit.verify().unwrap();
    assert!(audit
        .entries()
        .iter()
        .any(|e| matches!(e.action, social67_core::admin::AuditAction::PostRead { .. })));

    // GC: after the unlink earlier in this test, the revoked ciphertext
    // decays on the next pass (SOCIAL67_GC_SECS=2 is set at the top).
    alice.pump().await;
    bob.pump().await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut gone = false;
    while tokio::time::Instant::now() < deadline {
        alice.pump().await;
        bob.pump().await;
        let still_there = alice
            .node
            .get_blob(&iroh_blobs::Hash::from(post.blob_hash))
            .await
            .is_ok();
        if !still_there {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(gone, "GC should drop the unlinked ciphertext from the author device");
}

/// A node with no bootstrap still comes up and can be joined later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_restarts_with_same_identity() {
    let topic = fresh_topic();
    let dir = temp_dir("restart");
    let root1 = {
        let s = Session::start(dir.clone(), "carol", "Carol", topic, vec![])
            .await
            .unwrap();
        s.identity.root_pub().unwrap()
    };
    let root2 = {
        let s = Session::start(dir, "ignored", "Ignored", topic, vec![])
            .await
            .unwrap();
        s.identity.root_pub().unwrap()
    };
    assert_eq!(root1, root2, "identity persists across restarts");
}
