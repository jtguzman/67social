//! 67Social app shell — Tauri 2 commands bridging the Svelte UI to the
//! shared Rust core, in-process, no network hop.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use social67_core::feed::Feed;
use social67_core::keys::PubKey;
use social67_core::records::{Audience, Hash, Scale};
use social67_core::session::{fresh_topic, BlobKind, Session, SessionEvent};
use social67_core::net::Invite;
use tauri::{AppHandle, Manager, State};
use tokio::sync::Mutex;

/// Shared app state: the session (once started) + thumbnail data-URL
/// caches so the feed doesn't re-decrypt on every tick.
pub struct AppState {
    session: Mutex<Option<Arc<Mutex<Session>>>>,
    thumb_cache: Mutex<HashMap<String, String>>,
    full_cache: Mutex<HashMap<String, String>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            session: Mutex::new(None),
            thumb_cache: Mutex::new(HashMap::new()),
            full_cache: Mutex::new(HashMap::new()),
        }
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
    let bytes = data_encoding::HEXLOWER
        .decode(s.trim().as_bytes())
        .map_err(|e| format!("bad hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())
}

fn parse_pub(s: &str) -> Result<PubKey, String> {
    Ok(PubKey(unhex32(s)?))
}

// ---------- UI snapshot types ----------

#[derive(Serialize, Clone)]
struct UiMe {
    root: String,
    handle: String,
    display_name: String,
    endpoint: String,
}

#[derive(Serialize, Clone)]
struct UiPerson {
    root: String,
    handle: Option<String>,
    display_name: Option<String>,
}

#[derive(Serialize, Clone)]
struct UiReactionAgg {
    scale: String,
    emoji: String,
    avg: f64,
    count: u32,
    my_value: Option<u8>,
}

#[derive(Serialize, Clone)]
struct UiPost {
    id: String,
    author: String,
    author_handle: Option<String>,
    caption: Option<String>,
    audience: String,
    created_at: u64,
    unlinked: bool,
    thumb_data_url: Option<String>,
    reactions: Vec<UiReactionAgg>,
    mine: bool,
}

#[derive(Serialize, Clone)]
struct UiState {
    me: UiMe,
    invite: String,
    posts: Vec<UiPost>,
    directory: Vec<UiPerson>,
    pending_follow_requests: Vec<UiPerson>,
    pending_message_requests: Vec<UiPerson>,
    followers: Vec<String>,
    following: Vec<String>,
    open_chats: Vec<String>,
}

fn scale_info(s: Scale) -> (&'static str, &'static str) {
    match s {
        Scale::Stars => ("stars", "★"),
        Scale::Hearts => ("hearts", "❤"),
        Scale::Fire => ("fire", "🔥"),
    }
}

fn person(feed: &Feed, root: &PubKey) -> UiPerson {
    let entry = feed.directory.get(root);
    UiPerson {
        root: hex(&root.0),
        handle: entry.map(|e| e.handle.clone()),
        display_name: entry.map(|e| e.display_name.clone()),
    }
}

async fn build_state(state: &AppState, session: &Session) -> UiState {
    let feed = &session.feed;
    let me_root = feed.me.expect("session has identity");

    let mut posts: Vec<UiPost> = vec![];
    for entry in feed.posts.values() {
        let post = &entry.env.payload;
        let id = hex(&post.id);

        let thumb_data_url = if entry.unlinked {
            None
        } else {
            // Cache hit or decrypt now.
            let cache = state.thumb_cache.lock().await;
            if let Some(url) = cache.get(&id) {
                Some(url.clone())
            } else {
                drop(cache);
                match session.decrypt_blob(post, BlobKind::Thumb).await {
                    Some(bytes) => {
                        let url = format!(
                            "data:image/jpeg;base64,{}",
                            base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &bytes
                            )
                        );
                        state
                            .thumb_cache
                            .lock()
                            .await
                            .insert(id.clone(), url.clone());
                        Some(url)
                    }
                    None => None,
                }
            }
        };

        let content_key = session.content_key_for(post);
        let caption = content_key
            .as_ref()
            .and_then(|k| Feed::open_caption(post, k));

        let reactions = feed
            .aggregate(&post.id)
            .into_iter()
            .map(|(scale, avg, count)| {
                let (name, emoji) = scale_info(scale);
                UiReactionAgg {
                    scale: name.to_string(),
                    emoji: emoji.to_string(),
                    avg,
                    count,
                    my_value: feed.my_reaction(&post.id, &me_root, scale),
                }
            })
            .collect();

        posts.push(UiPost {
            id,
            author: hex(&post.author.0),
            author_handle: feed.directory.get(&post.author).map(|e| e.handle.clone()),
            caption,
            audience: match &post.audience {
                Audience::Public => "public".to_string(),
                Audience::Followers { .. } => "followers".to_string(),
            },
            created_at: post.created_at,
            unlinked: entry.unlinked,
            thumb_data_url,
            reactions,
            mine: post.author == me_root,
        });
    }
    posts.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    UiState {
        me: UiMe {
            root: hex(&me_root.0),
            handle: session.identity.handle.clone(),
            display_name: session.identity.display_name.clone(),
            endpoint: session.node.node_id().to_string(),
        },
        invite: session.invite().encode(),
        posts,
        directory: feed
            .directory
            .keys()
            .filter(|r| **r != me_root)
            .map(|r| person(feed, r))
            .collect(),
        pending_follow_requests: feed
            .pending_follow_requests
            .keys()
            .map(|r| person(feed, r))
            .collect(),
        pending_message_requests: feed
            .pending_message_requests
            .keys()
            .map(|r| person(feed, r))
            .collect(),
        followers: feed.my_followers.iter().map(|r| hex(&r.0)).collect(),
        following: feed.following.iter().map(|r| hex(&r.0)).collect(),
        open_chats: feed.open_chats.iter().map(|r| hex(&r.0)).collect(),
    }
}

async fn get_session(state: &State<'_, AppState>) -> Result<Arc<Mutex<Session>>, String> {
    let guard = state.session.lock().await;
    guard.clone().ok_or_else(|| "session not started".to_string())
}

// ---------- Commands ----------

#[tauri::command]
async fn start(
    app: AppHandle,
    state: State<'_, AppState>,
    handle: String,
    display_name: String,
    invite: Option<String>,
) -> Result<(), String> {
    {
        let guard = state.session.lock().await;
        if guard.is_some() {
            return Ok(());
        }
    }

    let data_dir = std::env::var("SOCIAL67_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            app.path()
                .app_data_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("./67social-data"))
        });
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;

    let (topic, bootstrap, inviter) = match invite {
        Some(raw) => {
            let inv = Invite::decode(&raw).map_err(|e| e.to_string())?;
            (inv.topic, vec![inv.node_id()], Some(inv.addr))
        }
        None => (fresh_topic(), vec![], None),
    };

    let session = Session::start(data_dir, &handle, &display_name, topic, bootstrap)
        .await
        .map_err(|e| e.to_string())?;

    // Dial the inviter directly and mesh in gossip.
    if let Some(addr) = inviter {
        let id = addr.id;
        session.add_peer_addr(addr);
        session
            .join_gossip_peer(id)
            .await
            .map_err(|e| e.to_string())?;
    }

    let arc = Arc::new(Mutex::new(session));
    let mut guard = state.session.lock().await;
    *guard = Some(arc);
    Ok(())
}

#[tauri::command]
async fn get_state(state: State<'_, AppState>) -> Result<UiState, String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    session.pump().await;
    Ok(build_state(&state, &session).await)
}

#[tauri::command]
async fn drain_events(state: State<'_, AppState>) -> Result<Vec<SessionEvent>, String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    Ok(session.events.drain(..).collect())
}

#[tauri::command]
async fn publish_post(
    state: State<'_, AppState>,
    image: Vec<u8>,
    caption: String,
    audience: String,
) -> Result<String, String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    let me = session.feed.me.ok_or("no identity")?;
    let aud = match audience.as_str() {
        "followers" => Audience::Followers { author: me },
        _ => Audience::Public,
    };
    let id = session
        .create_post(&image, &caption, aud)
        .await
        .map_err(|e| e.to_string())?;
    Ok(hex(&id))
}

#[tauri::command]
async fn react(state: State<'_, AppState>, post_id: String, scale: String, value: u8) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    let scale = match scale.as_str() {
        "stars" => Scale::Stars,
        "hearts" => Scale::Hearts,
        "fire" => Scale::Fire,
        _ => return Err("unknown scale".into()),
    };
    session
        .react(&unhex32(&post_id)?, scale, value)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn unlink(state: State<'_, AppState>, post_id: String) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    let id: Hash = unhex32(&post_id)?;
    session.unlink(&id).await.map_err(|e| e.to_string())?;
    state.thumb_cache.lock().await.remove(&post_id);
    state.full_cache.lock().await.remove(&post_id);
    Ok(())
}

#[tauri::command]
async fn request_follow(state: State<'_, AppState>, root: String) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    session
        .request_follow(parse_pub(&root)?)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn accept_follow(state: State<'_, AppState>, root: String) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    session
        .accept_follow(&parse_pub(&root)?)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn decline_follow(state: State<'_, AppState>, root: String) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    session.decline_follow(&parse_pub(&root)?);
    Ok(())
}

#[tauri::command]
async fn remove_follower(state: State<'_, AppState>, root: String) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    session
        .remove_follower(&parse_pub(&root)?)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn request_message(state: State<'_, AppState>, root: String) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    session
        .request_message(parse_pub(&root)?)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn accept_message(state: State<'_, AppState>, root: String) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    session
        .accept_message(&parse_pub(&root)?)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn decline_message(state: State<'_, AppState>, root: String) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    session.decline_message(&parse_pub(&root)?);
    Ok(())
}

#[tauri::command]
async fn end_chat(state: State<'_, AppState>, root: String) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    session.end_chat(&parse_pub(&root)?);
    Ok(())
}

#[tauri::command]
async fn block_user(state: State<'_, AppState>, root: String) -> Result<(), String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    session.block_user(&parse_pub(&root)?);
    Ok(())
}

#[tauri::command]
async fn send_chat(state: State<'_, AppState>, root: String, body: String) -> Result<bool, String> {
    let arc = get_session(&state).await?;
    let mut session = arc.lock().await;
    match session.send_chat(parse_pub(&root)?, &body).await {
        Ok(()) => Ok(true),
        Err(_) => Ok(false), // held in outbox — delivered on reconnect
    }
}

/// Fetch + decrypt the FULL image of a post, on demand (the feed only
/// loads thumbnails). Returns a JPEG data URL, or null when the post is
/// unlinked / the key is missing / the ciphertext is unreachable.
#[tauri::command]
async fn get_full_image(state: State<'_, AppState>, post_id: String) -> Result<Option<String>, String> {
    let id: Hash = unhex32(&post_id)?;
    // Cache hit (fast path, no session lock).
    {
        let cache = state.full_cache.lock().await;
        if let Some(url) = cache.get(&post_id) {
            return Ok(Some(url.clone()));
        }
    }
    let arc = get_session(&state).await?;
    let session = arc.lock().await;
    let Some(entry) = session.feed.posts.get(&id).filter(|e| !e.unlinked) else {
        return Ok(None);
    };
    let post = entry.env.payload.clone();
    match session.decrypt_blob(&post, BlobKind::Image).await {
        Some(bytes) => {
            let url = format!(
                "data:image/jpeg;base64,{}",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
            );
            state
                .full_cache
                .lock()
                .await
                .insert(post_id, url.clone());
            Ok(Some(url))
        }
        None => Ok(None),
    }
}

#[tauri::command]
async fn get_invite(state: State<'_, AppState>) -> Result<String, String> {
    let guard = state.session.lock().await;
    let arc = guard.clone().ok_or_else(|| "session not started".to_string())?;
    let session = arc.lock().await;
    Ok(session.invite().encode())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            start,
            get_state,
            drain_events,
            publish_post,
            react,
            get_full_image,
            unlink,
            request_follow,
            accept_follow,
            decline_follow,
            remove_follower,
            request_message,
            accept_message,
            decline_message,
            end_chat,
            block_user,
            send_chat,
            get_invite,
        ])
        .run(tauri::generate_context!())
        .expect("error while running 67Social");
}
