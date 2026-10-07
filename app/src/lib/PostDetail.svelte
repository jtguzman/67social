<script lang="ts">
  import { onMount } from "svelte";
  import { createEventDispatcher } from "svelte";
  import * as api from "./api";
  import ReactionBar from "./ReactionBar.svelte";

  export let post: api.UiPost;
  const dispatch = createEventDispatcher();

  let fullImage: string | null = null;
  let loading = true;
  let notFound = false;

  onMount(async () => {
    const url = await api.getFullImage(post.id);
    if (url) {
      fullImage = url;
    } else {
      notFound = true;
    }
    loading = false;
  });

  const time = new Date(post.created_at).toLocaleString();
</script>

<div class="overlay" on:click|self={() => dispatch("close")}>
  <div class="detail">
    <header>
      <span class="author">@{post.author_handle ?? post.author.slice(0, 10) + "…"}</span>
      <span class="audience">{post.audience === "public" ? "🌐 public" : "🔒 followers"}</span>
      <span class="time">{time}</span>
      <button class="close" on:click={() => dispatch("close")}>✕</button>
    </header>

    {#if loading}
      <div class="placeholder">Fetching & decrypting…</div>
    {:else if post.unlinked}
      <div class="placeholder">
        Unlinked — the ciphertext is being garbage-collected.
      </div>
    {:else if fullImage}
      <img src={fullImage} alt={post.caption ?? "post image"} />
    {:else if notFound}
      <div class="placeholder">
        🔒 Could not open: you don't hold this audience's key, or no replica has the ciphertext.
      </div>
    {/if}

    {#if post.caption}
      <p class="caption">{post.caption}</p>
    {/if}

    {#if !post.unlinked}
      <ReactionBar {post} on:changed={() => dispatch("changed")} />
    {/if}
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(5, 5, 12, 0.85);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }
  .detail {
    background: #16161f;
    border: 1px solid #26263a;
    border-radius: 14px;
    padding: 16px;
    max-width: 92vw;
    max-height: 90vh;
    overflow-y: auto;
    width: min(640px, 92vw);
  }
  header {
    display: flex;
    gap: 10px;
    align-items: baseline;
    margin-bottom: 12px;
  }
  .author {
    color: #8ab4ff;
    font-weight: 600;
  }
  .audience {
    color: #777;
    font-size: 12px;
  }
  .time {
    color: #555;
    font-size: 12px;
    margin-left: auto;
  }
  .close {
    background: none;
    border: none;
    color: #999;
    font-size: 16px;
    cursor: pointer;
  }
  img {
    width: 100%;
    border-radius: 10px;
    display: block;
  }
  .placeholder {
    background: #101018;
    border-radius: 10px;
    padding: 40px 20px;
    text-align: center;
    color: #888;
  }
  .caption {
    margin: 12px 0 4px;
    line-height: 1.4;
  }
</style>
