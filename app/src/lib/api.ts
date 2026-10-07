import { invoke } from "@tauri-apps/api/core";

export interface UiMe {
  root: string;
  handle: string;
  display_name: string;
  endpoint: string;
}

export interface UiPerson {
  root: string;
  handle: string | null;
  display_name: string | null;
}

export interface UiReactionAgg {
  scale: string;
  emoji: string;
  avg: number;
  count: number;
  my_value: number | null;
}

export interface UiPost {
  id: string;
  author: string;
  author_handle: string | null;
  caption: string | null;
  audience: string;
  created_at: number;
  unlinked: boolean;
  thumb_data_url: string | null;
  reactions: UiReactionAgg[];
  mine: boolean;
}

export interface UiState {
  me: UiMe;
  invite: string;
  posts: UiPost[];
  directory: UiPerson[];
  pending_follow_requests: UiPerson[];
  pending_message_requests: UiPerson[];
  followers: string[];
  following: string[];
  open_chats: string[];
}

export type SessionEvent =
  | { Feed: Record<string, unknown> }
  | { ChatReceived: { from: number[]; body: string; sent_at: number } }
  | { ChatUndeliverable: { to: number[]; body: string } }
  | { JoinedTopic: string };

export function bytesToHex(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------- Commands ----------

export const start = (handle: string, displayName: string, invite: string | null) =>
  invoke<void>("start", { handle, displayName, invite });

export const getState = () => invoke<UiState>("get_state");
export const drainEvents = () => invoke<SessionEvent[]>("drain_events");

export const publishPost = (image: number[], caption: string, audience: string) =>
  invoke<string>("publish_post", { image, caption, audience });

export const react = (postId: string, scale: string, value: number) =>
  invoke<void>("react", { postId, scale, value });

/** Fetch + decrypt the full image (JPEG data URL), or null. */
export const getFullImage = (postId: string) =>
  invoke<string | null>("get_full_image", { postId });

export const unlink = (postId: string) => invoke<void>("unlink", { postId });

export const requestFollow = (root: string) => invoke<void>("request_follow", { root });
export const acceptFollow = (root: string) => invoke<void>("accept_follow", { root });
export const declineFollow = (root: string) => invoke<void>("decline_follow", { root });
export const removeFollower = (root: string) => invoke<void>("remove_follower", { root });

export const requestMessage = (root: string) => invoke<void>("request_message", { root });
export const acceptMessage = (root: string) => invoke<void>("accept_message", { root });
export const declineMessage = (root: string) => invoke<void>("decline_message", { root });
export const endChat = (root: string) => invoke<void>("end_chat", { root });
export const blockUser = (root: string) => invoke<void>("block_user", { root });

/** Returns true when delivered immediately; false when held in the outbox. */
export const sendChat = (root: string, body: string) => invoke<boolean>("send_chat", { root, body });

// ---------- Ephemeral chat persistence (this device only) ----------

export interface ChatMessage {
  from: string;
  body: string;
  at: number;
  mine: boolean;
  delivered: boolean;
}

function chatKey(meRoot: string, peerRoot: string): string {
  return `67social.chat.${meRoot}.${peerRoot}`;
}

export function loadChat(meRoot: string, peerRoot: string): ChatMessage[] {
  try {
    return JSON.parse(localStorage.getItem(chatKey(meRoot, peerRoot)) ?? "[]");
  } catch {
    return [];
  }
}

export function appendChat(meRoot: string, peerRoot: string, msg: ChatMessage): void {
  const msgs = loadChat(meRoot, peerRoot);
  msgs.push(msg);
  localStorage.setItem(chatKey(meRoot, peerRoot), JSON.stringify(msgs));
}

export function dropChat(meRoot: string, peerRoot: string): void {
  localStorage.removeItem(chatKey(meRoot, peerRoot));
}
