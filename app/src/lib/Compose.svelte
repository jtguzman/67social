<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import * as api from "./api";

  export let me: api.UiMe;
  const dispatch = createEventDispatcher();

  let caption = "";
  let audience: "public" | "followers" = "followers";
  let file: File | null = null;
  let preview: string | null = null;
  let busy = false;
  let error: string | null = null;

  function onFile(e: Event) {
    const input = e.target as HTMLInputElement;
    file = input.files?.[0] ?? null;
    if (file) {
      const reader = new FileReader();
      reader.onload = () => (preview = reader.result as string);
      reader.readAsDataURL(file);
    } else {
      preview = null;
    }
  }

  async function publish() {
    if (!file) {
      error = "Choose an image first";
      return;
    }
    busy = true;
    error = null;
    try {
      const buf = new Uint8Array(await file.arrayBuffer());
      // The core validates by decoding, strips EXIF/GPS, normalizes to
      // 2048px + thumbnail, encrypts, and only then stores. The original
      // never leaves this device.
      await api.publishPost(Array.from(buf), caption.trim(), audience);
      dispatch("posted");
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="compose">
  <h2>New post</h2>

  <label class="file">
    <input type="file" accept="image/*" on:change={onFile} />
    {#if preview}
      <img src={preview} alt="preview" />
    {:else}
      <span>Choose an image…</span>
    {/if}
  </label>

  <textarea bind:value={caption} rows="3" placeholder="Caption (encrypted for followers-only posts)"></textarea>

  <div class="audience">
    <label>
      <input type="radio" bind:group={audience} value="followers" />
      🔒 Followers — only people you've accepted hold the key
    </label>
    <label>
      <input type="radio" bind:group={audience} value="public" />
      🌐 Public — anyone on the network can decrypt
    </label>
  </div>

  {#if error}<p class="error">{error}</p>{/if}

  <button on:click={publish} disabled={busy || !file}>
    {busy ? "Encrypting & publishing…" : "Publish"}
  </button>

  <p class="note">
    On publish: the image is decoded (rejected if not a real image), stripped of EXIF/GPS metadata,
    resized to 2048px with a small thumbnail, encrypted with a fresh content key, chunked and
    content-addressed with BLAKE3, and the signed record is gossiped. Storage nodes only ever hold
    ciphertext.
  </p>
</div>

<style>
  .compose {
    display: flex;
    flex-direction: column;
    gap: 14px;
    margin-top: 18px;
  }
  h2 {
    margin: 0;
    font-size: 18px;
  }
  .file {
    border: 2px dashed #33334a;
    border-radius: 12px;
    min-height: 160px;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    overflow: hidden;
    color: #777;
  }
  .file input {
    display: none;
  }
  .file img {
    width: 100%;
    display: block;
  }
  textarea {
    background: #1a1a2a;
    border: 1px solid #33334a;
    color: #eee;
    border-radius: 8px;
    padding: 10px;
    font-size: 15px;
    resize: vertical;
  }
  .audience {
    display: flex;
    flex-direction: column;
    gap: 8px;
    font-size: 14px;
    color: #c0c0d0;
  }
  button {
    background: #4a6fd4;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 12px;
    font-size: 16px;
    cursor: pointer;
  }
  button:disabled {
    opacity: 0.5;
  }
  .error {
    color: #ff8080;
  }
  .note {
    color: #666;
    font-size: 12px;
    line-height: 1.6;
  }
</style>
