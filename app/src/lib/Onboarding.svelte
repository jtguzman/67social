<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import * as api from "./api";

  const dispatch = createEventDispatcher();

  let handle = "";
  let displayName = "";
  let invite = "";
  let busy = false;
  let error: string | null = null;

  async function go() {
    if (!handle.trim()) {
      error = "Pick a handle";
      return;
    }
    busy = true;
    error = null;
    try {
      await api.start(handle.trim(), displayName.trim() || handle.trim(), invite.trim() || null);
      dispatch("started");
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="onboarding">
  <h1>67Social</h1>
  <p class="tagline">
    Photos live encrypted on your own devices. Only people holding the right key can see them.
    No central host.
  </p>

  <label>
    Handle
    <input bind:value={handle} placeholder="jtg" />
  </label>
  <label>
    Display name
    <input bind:value={displayName} placeholder="Jose Tomas" />
  </label>
  <label>
    Invite <span class="opt">(optional — join an existing network)</span>
    <textarea bind:value={invite} rows="3" placeholder="paste an invite string"></textarea>
  </label>

  {#if error}<p class="error">{error}</p>{/if}

  <button on:click={go} disabled={busy}>
    {busy ? "Starting node…" : invite.trim() ? "Join network" : "Start new network"}
  </button>

  <p class="note">
    Your keys are generated on this device and never leave it. The root key anchors your account;
    this device's key signs your posts.
  </p>
</div>

<style>
  .onboarding {
    max-width: 420px;
    margin: 8vh auto;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  h1 {
    color: #8ab4ff;
    margin: 0;
  }
  .tagline {
    color: #9a9ab0;
    line-height: 1.5;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 14px;
    color: #c0c0d0;
  }
  input,
  textarea {
    background: #1a1a2a;
    border: 1px solid #33334a;
    color: #eee;
    border-radius: 8px;
    padding: 10px;
    font-size: 15px;
  }
  .opt {
    color: #666;
    font-size: 12px;
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
    font-size: 13px;
    line-height: 1.5;
  }
</style>
