<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import * as api from "./api";

  export let post: api.UiPost;
  const dispatch = createEventDispatcher();

  const scales = ["stars", "hearts", "fire"] as const;
  const emojiFor: Record<string, string> = { stars: "★", hearts: "❤", fire: "🔥" };

  let busy = false;

  function aggFor(scale: string): api.UiReactionAgg | undefined {
    return post.reactions.find((r) => r.scale === scale);
  }

  async function rate(scale: string, value: number) {
    if (busy || post.unlinked) return;
    busy = true;
    try {
      await api.react(post.id, scale, value);
      dispatch("changed");
    } finally {
      busy = false;
    }
  }
</script>

<div class="reactions">
  {#each scales as scale}
    {@const agg = aggFor(scale)}
    <div class="scale">
      <span class="emoji">{emojiFor[scale]}</span>
      <div class="pips">
        {#each [1, 2, 3, 4, 5] as v}
          <button
            class="pip"
            class:mine={(agg?.my_value ?? 0) >= v}
            on:click={() => rate(scale, v)}
            title="rate {v}/5"
          ></button>
        {/each}
      </div>
      {#if agg && agg.count > 0}
        <span class="agg">{agg.avg.toFixed(1)} from {agg.count}</span>
      {/if}
    </div>
  {/each}
</div>

<style>
  .reactions {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px 0;
  }
  .scale {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .emoji {
    width: 22px;
    text-align: center;
    color: #f0c060;
  }
  .pips {
    display: flex;
    gap: 3px;
  }
  .pip {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    border: 1px solid #44445a;
    background: transparent;
    cursor: pointer;
    padding: 0;
  }
  .pip:hover {
    border-color: #8ab4ff;
  }
  .pip.mine {
    background: #8ab4ff;
    border-color: #8ab4ff;
  }
  .agg {
    color: #777;
    font-size: 12px;
  }
</style>
