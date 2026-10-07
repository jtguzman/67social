<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import * as api from "./lib/api";
  import Onboarding from "./lib/Onboarding.svelte";
  import Feed from "./lib/Feed.svelte";
  import Compose from "./lib/Compose.svelte";
  import People from "./lib/People.svelte";
  import Requests from "./lib/Requests.svelte";
  import Chats from "./lib/Chats.svelte";
  import PostDetail from "./lib/PostDetail.svelte";

  let state: api.UiState | null = null;
  let error: string | null = null;
  let tab: "feed" | "compose" | "people" | "requests" | "chats" = "feed";
  let timer: ReturnType<typeof setInterval> | null = null;
  let openPostId: string | null = null;

  $: openPost = state?.posts.find((p) => p.id === openPostId) ?? null;

  async function refresh() {
    try {
      state = await api.getState();
      error = null;
    } catch (e) {
      error = String(e);
    }
    try {
      const events = await api.drainEvents();
      for (const ev of events) {
        if ("ChatReceived" in ev && state) {
          const from = api.bytesToHex(ev.ChatReceived.from);
          api.appendChat(state.me.root, from, {
            from,
            body: ev.ChatReceived.body,
            at: ev.ChatReceived.sent_at,
            mine: false,
            delivered: true,
          });
          window.dispatchEvent(new CustomEvent("chat-updated", { detail: from }));
        }
      }
    } catch {
      /* events are best-effort */
    }
  }

  function onStarted() {
    refresh();
    timer = setInterval(refresh, 1500);
  }

  onDestroy(() => {
    if (timer) clearInterval(timer);
  });
</script>

<main>
  {#if !state}
    <Onboarding on:started={onStarted} />
  {:else}
    <header>
      <h1>67Social</h1>
      <nav>
        <button class:active={tab === "feed"} on:click={() => (tab = "feed")}>Feed</button>
        <button class:active={tab === "compose"} on:click={() => (tab = "compose")}>Post</button>
        <button class:active={tab === "people"} on:click={() => (tab = "people")}>People</button>
        <button class:active={tab === "requests"} on:click={() => (tab = "requests")}>
          Requests
          {#if state.pending_follow_requests.length + state.pending_message_requests.length > 0}
            <span class="badge">
              {state.pending_follow_requests.length + state.pending_message_requests.length}
            </span>
          {/if}
        </button>
        <button class:active={tab === "chats"} on:click={() => (tab = "chats")}>Chats</button>
      </nav>
      <div class="me">@{state.me.handle}</div>
    </header>

    {#if error}
      <p class="error">{error}</p>
    {/if}

    {#if tab === "feed"}
      <Feed {state} on:changed={refresh} on:open={(e) => (openPostId = e.detail.id)} />
    {:else if tab === "compose"}
      <Compose me={state.me} on:posted={() => { tab = "feed"; refresh(); }} />
    {:else if tab === "people"}
      <People {state} on:changed={refresh} />
    {:else if tab === "requests"}
      <Requests {state} on:changed={refresh} />
    {:else if tab === "chats"}
      <Chats {state} />
    {/if}

    <footer>
      <details>
        <summary>Invite (share out-of-band)</summary>
        <textarea readonly rows="3">{state.invite}</textarea>
        <p class="hint">
          Anyone with this string can join this network topic and dial this device directly.
        </p>
      </details>
    </footer>
  {/if}

  {#if openPost}
    <PostDetail post={openPost} on:close={() => (openPostId = null)} on:changed={refresh} />
  {/if}
</main>

<style>
  :global(body) {
    margin: 0;
    font-family: system-ui, -apple-system, sans-serif;
    background: #10101a;
    color: #e8e8f0;
  }
  main {
    max-width: 680px;
    margin: 0 auto;
    padding: 0 16px 64px;
  }
  header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 12px 0;
    border-bottom: 1px solid #2a2a3a;
    position: sticky;
    top: 0;
    background: #10101a;
    z-index: 10;
  }
  h1 {
    font-size: 20px;
    margin: 0;
    color: #8ab4ff;
  }
  nav {
    display: flex;
    gap: 4px;
    flex: 1;
  }
  nav button {
    background: none;
    border: none;
    color: #9a9ab0;
    padding: 8px 10px;
    cursor: pointer;
    border-radius: 8px;
    font-size: 14px;
  }
  nav button.active {
    background: #22223a;
    color: #fff;
  }
  .badge {
    background: #e0506a;
    color: white;
    border-radius: 10px;
    padding: 0 6px;
    font-size: 11px;
  }
  .me {
    color: #8ab4ff;
    font-size: 14px;
  }
  .error {
    color: #ff8080;
  }
  footer {
    margin-top: 32px;
    color: #777;
    font-size: 13px;
  }
  footer textarea {
    width: 100%;
    background: #1a1a2a;
    color: #aaa;
    border: 1px solid #333;
    border-radius: 8px;
    font-size: 11px;
  }
  .hint {
    color: #666;
  }
</style>
