<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import * as api from "./api";
  import PostCard from "./PostCard.svelte";

  export let state: api.UiState;
  const dispatch = createEventDispatcher();
</script>

<div>
  {#if state.posts.length === 0}
    <p class="empty">
      No posts yet. Publish one, or join someone's network with their invite to see theirs.
    </p>
  {/if}
  {#each state.posts as post (post.id)}
    <PostCard
      {post}
      on:changed={() => dispatch("changed")}
      on:open={(e) => dispatch("open", e.detail)}
    />
  {/each}
</div>

<style>
  .empty {
    color: #777;
    text-align: center;
    margin-top: 48px;
    line-height: 1.6;
  }
</style>
