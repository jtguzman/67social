<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import * as api from "./api";

  export let state: api.UiState;
  const dispatch = createEventDispatcher();

  async function act(fn: (root: string) => Promise<void>, root: string) {
    await fn(root);
    dispatch("changed");
  }
</script>

<div>
  <h2>People</h2>
  <p class="hint">
    The public directory: handles and keys, nothing private. Following is request-gated — accepting
    delivers your Followers audience key. Messaging is a separate gate.
  </p>

  {#if state.directory.length === 0}
    <p class="empty">No one else discovered yet. Share your invite (footer) to bring someone in.</p>
  {/if}

  {#each state.directory as person (person.root)}
    <div class="person">
      <div class="info">
        <span class="handle">@{person.handle ?? person.root.slice(0, 10) + "…"}</span>
        {#if person.display_name}<span class="name">{person.display_name}</span>{/if}
        {#if state.following.includes(person.root)}<span class="tag">following</span>{/if}
        {#if state.followers.includes(person.root)}<span class="tag">follows you</span>{/if}
      </div>
      <div class="actions">
        {#if !state.following.includes(person.root)}
          <button on:click={() => act(api.requestFollow, person.root)}>Request follow</button>
        {/if}
        {#if !state.open_chats.includes(person.root)}
          <button on:click={() => act(api.requestMessage, person.root)}>Request chat</button>
        {/if}
        {#if state.followers.includes(person.root)}
          <button class="warn" on:click={() => act(api.removeFollower, person.root)}>
            Remove follower (rotate key)
          </button>
        {/if}
        <button class="danger" on:click={() => act(api.blockUser, person.root)}>Block</button>
      </div>
    </div>
  {/each}
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
    margin: 32px 0;
  }
  .person {
    background: #16161f;
    border: 1px solid #26263a;
    border-radius: 10px;
    padding: 12px;
    margin: 10px 0;
  }
  .info {
    display: flex;
    gap: 10px;
    align-items: baseline;
    margin-bottom: 8px;
  }
  .handle {
    color: #8ab4ff;
    font-weight: 600;
  }
  .name {
    color: #9a9ab0;
  }
  .tag {
    background: #22223a;
    color: #9ab;
    font-size: 11px;
    border-radius: 8px;
    padding: 2px 8px;
  }
  .actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  button {
    background: #2a2a44;
    color: #dde;
    border: none;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 13px;
    cursor: pointer;
  }
  button.warn {
    background: #4a3a22;
    color: #d9b98a;
  }
  button.danger {
    background: #3a2222;
    color: #d98a8a;
  }
</style>
