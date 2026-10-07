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
  <h2>Requests</h2>

  {#if state.pending_follow_requests.length === 0 && state.pending_message_requests.length === 0}
    <p class="empty">No pending requests.</p>
  {/if}

  {#each state.pending_follow_requests as person (person.root)}
    <div class="request">
      <p>
        <span class="handle">@{person.handle ?? person.root.slice(0, 10) + "…"}</span>
        wants to follow you. Accepting delivers your current Followers audience key — they can
        decrypt your followers-only posts.
      </p>
      <div class="actions">
        <button class="accept" on:click={() => act(api.acceptFollow, person.root)}>Accept (deliver key)</button>
        <button on:click={() => act(api.declineFollow, person.root)}>Decline</button>
      </div>
    </div>
  {/each}

  {#each state.pending_message_requests as person (person.root)}
    <div class="request">
      <p>
        <span class="handle">@{person.handle ?? person.root.slice(0, 10) + "…"}</span>
        wants to chat. Accepting opens a direct, ephemeral chat — history lives only in each
        device's local storage, never on any node.
      </p>
      <div class="actions">
        <button class="accept" on:click={() => act(api.acceptMessage, person.root)}>Accept (open chat)</button>
        <button on:click={() => act(api.declineMessage, person.root)}>Decline</button>
      </div>
    </div>
  {/each}
</div>

<style>
  h2 {
    font-size: 18px;
  }
  .empty {
    color: #777;
  }
  .request {
    background: #16161f;
    border: 1px solid #26263a;
    border-radius: 10px;
    padding: 12px;
    margin: 10px 0;
  }
  .request p {
    margin: 0 0 10px;
    line-height: 1.5;
    color: #c0c0d0;
    font-size: 14px;
  }
  .handle {
    color: #8ab4ff;
    font-weight: 600;
  }
  .actions {
    display: flex;
    gap: 8px;
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
  button.accept {
    background: #2a4a3a;
    color: #9ad9b9;
  }
</style>
