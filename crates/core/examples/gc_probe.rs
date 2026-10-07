#[tokio::main(flavor="multi_thread", worker_threads=2)]
async fn main() {
    // Mirror net.rs: store with GC + KeepSet, add two blobs (tagged), drop
    // one tag, expect the sweep.
    let dir = std::env::temp_dir().join("s67-gc-probe6");
    let _ = std::fs::remove_dir_all(&dir);
    let keep = social67_core::net::KeepSet::default();
    let root = dir.join("blobs");
    let mut opts = iroh_blobs::store::fs::options::Options::new(&root);
    opts.gc = Some(iroh_blobs::store::GcConfig {
        interval: n0_future::time::Duration::from_secs(2),
        add_protected: Some(social67_core::net::keep_protect_cb(&keep)),
    });
    let s = iroh_blobs::store::fs::FsStore::load_with_opts(root.join("blobs.db"), opts).await.unwrap();

    // replicate add_blob semantics
    async fn add(s: &iroh_blobs::store::fs::FsStore, b: &[u8]) -> iroh_blobs::Hash {
        let tt = s.blobs().add_slice(b).temp_tag().await.unwrap();
        let h = tt.hash();
        let haf = tt.hash_and_format();
        drop(tt);
        s.tags().set(h.to_string(), haf).await.unwrap();
        h
    }
    let kept = add(&s, b"y").await;
    let dropped = add(&s, b"x").await;
    keep.replace([kept]); // both tagged AND in keep set
    s.tags().delete(dropped.to_string()).await.unwrap(); // unlink: drop tag
    keep.replace([]); // keep set only has kept now
    println!("waiting for gc pass…");
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if s.get_bytes(dropped).await.is_err() {
            assert_eq!(&s.get_bytes(kept).await.unwrap()[..], b"y");
            println!("OK: unprotected blob swept, protected blob survives");
            return;
        }
    }
    panic!("GC never swept the unprotected blob");
}
