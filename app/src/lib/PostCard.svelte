<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import * as api from "./api";
  import ReactionBar from "./ReactionBar.svelte";

  export let post: api.UiPost;
  const dispatch = createEventDispatcher();

  let confirmingUnlink = false;

  async function doUnlink() {
    if (!confirmingUnlink) {
      confirmingUnlink = true;
      return;
    }
    await api.unlink(post.id);
    dispatch("changed");
  }

  const time = new Date(post.created_at).toLocaleString();
</script>

<article class:unlinked={post.unlinked}>
  <header>
    <span class="author">@{post.author_handle ?? post.author.slice(0, 10) + "…"}</span>
    <span class="audience">{post.audience === "public" ? "🌐 public" : "🔒 followers"}</span>
    <span class="time">{time}</span>
  </header>

  {#if post.unlinked}
    <div class="gone">
      <p>Unlinked by the author.</p>
      <p class="hint">
        The network stopped distributing this image and no one new can open it. Anyone who already
        decrypted and saved a copy keeps it.
      </p>
    </div>
  {:else if post.thumb_data_url}
    <button class="thumb-btn" on:click={() => dispatch("open", post)}>
      <img src={post.thumb_data_url} alt={post.caption ?? "post image"} />
    </button>
  {:else}
    <div class="locked">
      <p>🔒 Encrypted — you don't hold this audience's key.</p>
    </div>
  {/if}

  {#if post.caption}
    <p class="caption">{post.caption}</p>
  {/if}

  {#if !post.unlinked}
    <ReactionBar {post} on:changed={() => dispatch("changed")} />
  {/if}

  {#if post.mine && !post.unlinked}
    <button class="unlink" class:confirm={confirmingUnlink} on:click={doUnlink}>
      {confirmingUnlink ? "Confirm unlink — this destroys the key" : "Unlink"}
    </button>
  {/if}
</article>

<style>
  article {
    background: #16161f;
    border: 1px solid #26263a;
    border-radius: 12px;
    padding: 14px;
    margin: 14px 0;
  }
  article.unlinked {
    opacity: 0.6;
  }
  header {
    display: flex;
    gap: 10px;
    align-items: baseline;
    margin-bottom: 10px;
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
  .thumb-btn {
    padding: 0;
    border: none;
    background: none;
    cursor: zoom-in;
    width: 100%;
    border-radius: 8px;
  }
  img {
    width: 100%;
    border-radius: 8px;
    display: block;
  }
  .locked,
  .gone {
    background: #101018;
    border-radius: 8px;
    padding: 24px;
    text-align: center;
    color: #888;
  }
  .hint {
    font-size: 12px;
    color: #555;
  }
  .caption {
    margin: 10px 0 4px;
    line-height: 1.4;
  }
  .unlink {
    background: none;
    border: 1px solid #553;
    color: #c9a;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 12px;
    cursor: pointer;
  }
  .unlink.confirm {
    background: #622;
    color: #fff;
    border-color: #a44;
  }
</style>
