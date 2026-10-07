<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import * as api from "./api";

  export let state: api.UiState;

  let openPeer: string | null = null;
  let messages: api.ChatMessage[] = [];
  let draft = "";
  let scroller: HTMLElement;

  function handleFor(root: string): string {
    const p = state.directory.find((d) => d.root === root);
    return p?.handle ?? root.slice(0, 10) + "…";
  }

  function open(peer: string) {
    openPeer = peer;
    messages = api.loadChat(state.me.root, peer);
    setTimeout(() => scroller?.scrollTo(0, scroller.scrollHeight), 0);
  }

  function reload() {
    if (openPeer) {
      messages = api.loadChat(state.me.root, openPeer);
    }
  }

  function onChatUpdated(e: Event) {
    const from = (e as CustomEvent<string>).detail;
    if (from === openPeer) reload();
  }

  async function send() {
    const body = draft.trim();
    if (!body || !openPeer) return;
    draft = "";
    const delivered = await api.sendChat(openPeer, body);
    api.appendChat(state.me.root, openPeer, {
      from: state.me.root,
      body,
      at: Date.now(),
      mine: true,
      delivered,
    });
    reload();
    setTimeout(() => scroller?.scrollTo(0, scroller.scrollHeight), 0);
  }

  async function end() {
    if (!openPeer) return;
    await api.endChat(openPeer);
    api.dropChat(state.me.root, openPeer);
    openPeer = null;
  }

  onMount(() => window.addEventListener("chat-updated", onChatUpdated));
  onDestroy(() => window.removeEventListener("chat-updated", onChatUpdated));
</script>

<div class="chats">
  {#if !openPeer}
    <h2>Chats</h2>
    <p class="hint">
      Ephemeral by design: history lives only in this device's local storage. Clear app storage or
      switch devices and the conversation is gone. A message sent while the other person is offline
      is held by your device and delivered on reconnect.
    </p>
    {#if state.open_chats.length === 0}
      <p class="empty">No open chats. Accept a message request first (People → Request chat).</p>
    {/if}
    {#each state.open_chats as root (root)}
      <button class="chat-row" on:click={() => open(root)}>
        <span class="handle">@{handleFor(root)}</span>
        <span class="count">{api.loadChat(state.me.root, root).length} messages</span>
      </button>
    {/each}
  {:else}
    <div class="chat-head">
      <button class="back" on:click={() => (openPeer = null)}>←</button>
      <span class="handle">@{handleFor(openPeer)}</span>
      <button class="end" on:click={end}>End chat (drop history)</button>
    </div>
    <div class="messages" bind:this={scroller}>
      {#each messages as m}
        <div class="msg" class:mine={m.mine}>
          <span class="body">{m.body}</span>
          <span class="meta">
            {new Date(m.at).toLocaleTimeString()}
            {#if m.mine}{m.delivered ? "✓" : "…held"}{/if}
          </span>
        </div>
      {/each}
    </div>
    <div class="composer">
      <input
        bind:value={draft}
        placeholder="Message — end-to-end encrypted over a direct stream"
        on:keydown={(e) => e.key === "Enter" && send()}
      />
      <button on:click={send}>Send</button>
    </div>
  {/if}
</div>

<style>
  h2 {
    font-size: 18px;
  }
  .hint {
    color: #666;
    font-size: 13px;
    line-height: 1.5;
  }
  .empty {
    color: #777;
  }
  .chat-row {
    display: flex;
    justify-content: space-between;
    width: 100%;
    background: #16161f;
    border: 1px solid #26263a;
    border-radius: 10px;
    padding: 14px;
    margin: 8px 0;
    color: #dde;
    cursor: pointer;
    font-size: 15px;
  }
  .handle {
    color: #8ab4ff;
    font-weight: 600;
  }
  .count {
    color: #666;
    font-size: 13px;
  }
  .chat-head {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 0;
  }
  .back {
    background: none;
    border: none;
    color: #8ab4ff;
    font-size: 20px;
    cursor: pointer;
  }
  .end {
    margin-left: auto;
    background: #3a2222;
    color: #d98a8a;
    border: none;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 12px;
    cursor: pointer;
  }
  .messages {
    height: 50vh;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px;
    background: #12121c;
    border-radius: 10px;
  }
  .msg {
    max-width: 75%;
    background: #22223a;
    border-radius: 12px;
    padding: 8px 12px;
    align-self: flex-start;
  }
  .msg.mine {
    align-self: flex-end;
    background: #2a3a5a;
  }
  .body {
    display: block;
    line-height: 1.4;
  }
  .meta {
    display: block;
    font-size: 11px;
    color: #889;
    margin-top: 2px;
    text-align: right;
  }
  .composer {
    display: flex;
    gap: 8px;
    margin-top: 10px;
  }
  .composer input {
    flex: 1;
    background: #1a1a2a;
    border: 1px solid #33334a;
    color: #eee;
    border-radius: 8px;
    padding: 10px;
    font-size: 15px;
  }
  .composer button {
    background: #4a6fd4;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 0 20px;
    cursor: pointer;
  }
</style>
