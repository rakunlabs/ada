<script lang="ts">
  import { formToObject } from "./helper/form";
  import { login, LoginError } from "./helper/login";
  import { getRedirectPath, isResponseTypeCode } from "./helper/query";
  import { initTheme, toggleTheme, getTheme } from "./helper/theme";
  import type { AuthInfo, StrategyDescriptor } from "./helper/info";
  import { Sun, Moon, Eye, EyeOff, Loader2 } from "lucide-svelte";

  let error = $state("");
  let working = $state(false);
  let mounted = $state(false);
  let showPassword = $state(false);
  let isDark = $state(false);

  let authInfo: AuthInfo = $state({
    title: "Sign in",
    strategies: [],
  });

  let formStrategies = $derived(
    authInfo.strategies.filter(
      (s) => (s.fields?.length ?? 0) > 0 || s.kind === "password",
    ),
  );

  let redirectStrategies = $derived(
    authInfo.strategies.filter(
      (s) => (s.fields?.length ?? 0) === 0 && s.kind !== "password",
    ),
  );

  let selectedFormStrategy: string = $state("");

  $effect(() => {
    if (!selectedFormStrategy && formStrategies.length > 0) {
      selectedFormStrategy = formStrategies[0].name;
    }
  });

  let activeForm: StrategyDescriptor | undefined = $derived(
    formStrategies.find((s) => s.name === selectedFormStrategy),
  );

  const handleThemeToggle = () => {
    const next = toggleTheme();
    isDark = next === "dark";
  };

  const signin = async (
    e: SubmitEvent & { currentTarget: EventTarget & HTMLFormElement },
  ) => {
    e.preventDefault();
    e.stopPropagation();
    if (working || !activeForm) return;

    error = "";
    working = true;
    const data = formToObject(e.currentTarget);

    try {
      await login(activeForm.url, data);

      if (!isResponseTypeCode()) {
        window.location.assign(getRedirectPath());
        return;
      }

      window.location.replace(window.location.href);
    } catch (reason: unknown) {
      if (reason instanceof LoginError) {
        error =
          reason.status === 401
            ? "Invalid username or password"
            : reason.message;
      } else if (reason instanceof Error) {
        error = reason.message;
      } else {
        error = String(reason);
      }
    } finally {
      working = false;
    }
  };

  const fetchInfo = async () => {
    try {
      const endpoint = import.meta.env.VITE_API ?? "info";
      const res = await fetch(`./${endpoint}`);
      if (!res.ok) throw new Error(`Failed to load info (${res.status})`);
      authInfo = await res.json();
    } catch (err) {
      console.error(err);
    }
  };

  const getCookie = (name: string): string | undefined => {
    const match = document.cookie.match(
      new RegExp("(?:^|;\\s*)" + name + "=([^;]*)"),
    );
    return match ? decodeURIComponent(match[1]) : undefined;
  };

  const openOAuthPopup = (url: string) => {
    const win = window.open(url);
    const timer = setInterval(() => {
      if (win?.closed) {
        clearInterval(timer);
        if (getCookie("auth_success") === "true") {
          if (!isResponseTypeCode()) {
            window.location.assign(getRedirectPath());
            return;
          }
          window.location.replace(window.location.href);
        }
      }
    }, 500);
  };

  $effect(() => {
    initTheme();
    isDark = getTheme() === "dark";

    (async () => {
      await fetchInfo();

      const title = new URLSearchParams(window.location.search).get("title");
      if (title) authInfo.title = title;

      document.title = authInfo.title;
      mounted = true;
    })();
  });
</script>

<div class="page">
  <div class="container">
    <!-- Card -->
    <div class="card">
      <!-- Card header -->
      <div class="card-header">
        <div class="card-header-left">
          {#if authInfo.icon}
            <img
              src={authInfo.icon}
              alt=""
              class="icon"
              class:invisible={!mounted}
            />
          {/if}
          <div>
            <h1 class="title" class:invisible={!mounted}>{authInfo.title}</h1>
            {#if authInfo.subtitle}
              <p class="subtitle" class:invisible={!mounted}>
                {authInfo.subtitle}
              </p>
            {/if}
          </div>
        </div>
        <div class="card-header-right">
          {#if authInfo.version}
            <span class="version">{authInfo.version}</span>
          {/if}
          <button
            class="theme-toggle-inline"
            onclick={handleThemeToggle}
            aria-label="Toggle theme"
            type="button"
          >
            {#if isDark}
              <Sun size={16} />
            {:else}
              <Moon size={16} />
            {/if}
          </button>
        </div>
      </div>
      <!-- Form strategies -->
      {#if formStrategies.length}
        {#if formStrategies.length > 1}
          <div class="strategy-selector">
            {#each formStrategies as s}
              <button
                type="button"
                class="strategy-tab"
                class:active={selectedFormStrategy === s.name}
                onclick={() => {
                  selectedFormStrategy = s.name;
                  error = "";
                }}
              >
                {s.label}
              </button>
            {/each}
          </div>
        {/if}

        {#if activeForm}
          <form onsubmit={signin}>
            {#each activeForm.fields ?? [] as field (field.name)}
              <div class="field">
                <label for={field.name}>{field.label}</label>
                <div class="input-wrapper">
                  <input
                    id={field.name}
                    name={field.name}
                    type={field.type === "password"
                      ? showPassword
                        ? "text"
                        : "password"
                      : field.type}
                    required={field.required}
                    placeholder={field.placeholder ?? ""}
                    autocomplete={field.type === "password"
                      ? "current-password"
                      : field.name}
                  />
                  {#if field.type === "password"}
                    <button
                      type="button"
                      class="eye-toggle"
                      onclick={() => (showPassword = !showPassword)}
                      aria-label={showPassword
                        ? "Hide password"
                        : "Show password"}
                    >
                      {#if showPassword}
                        <EyeOff size={16} />
                      {:else}
                        <Eye size={16} />
                      {/if}
                    </button>
                  {/if}
                </div>
              </div>
            {/each}

            <button type="submit" class="btn-primary" disabled={working}>
              {#if working}
                <Loader2 size={16} class="spinner" />
              {/if}
              Sign in
            </button>
          </form>
        {/if}
      {/if}

      <!-- OAuth strategies -->
      {#if redirectStrategies.length}
        {#if formStrategies.length}
          <div class="divider">
            <span>or</span>
          </div>
        {/if}

        <div class="oauth-buttons">
          {#each redirectStrategies as s}
            <button
              type="button"
              class="btn-oauth"
              onclick={() => openOAuthPopup(s.url)}
            >
              {s.label}
            </button>
          {/each}
        </div>
      {/if}

      <!-- Error -->
      {#if error}
        <div class="error-banner">
          <span>{error}</span>
        </div>
      {/if}

    </div>
  </div>
</div>

<style>
  @reference "tailwindcss";

  .page {
    min-height: 100vh;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: 48px 16px 32px;
    position: relative;
  }

  .container {
    width: 100%;
    max-width: 400px;
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  .icon {
    height: 64px;
    width: 64px;
    object-fit: contain;
    flex-shrink: 0;
  }

  .card-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 20px;
  }

  .card-header-left {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .title {
    font-size: 22px;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0 0 4px;
    transition: color 0.2s;
  }

  .subtitle {
    font-size: 14px;
    color: var(--text-muted);
    margin: 0;
    transition: color 0.2s;
  }

  .theme-toggle-inline {
    flex-shrink: 0;
    width: 32px;
    height: 32px;
    border-radius: 6px;
    border: 1px solid var(--card-border);
    background: var(--toggle-bg);
    color: var(--toggle-text);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: all 0.15s;
    margin-top: 2px;

    &:hover {
      background: var(--toggle-hover);
    }
  }

  .invisible {
    visibility: hidden;
  }

  .card {
    width: 100%;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 28px;
    box-shadow: var(--card-shadow);
    transition: all 0.2s;
  }

  /* Strategy tabs */
  .strategy-selector {
    display: flex;
    gap: 4px;
    background: var(--bg);
    border-radius: 8px;
    padding: 3px;
    margin-bottom: 20px;
  }

  .strategy-tab {
    flex: 1;
    padding: 7px 12px;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
    background: transparent;
    color: var(--text-secondary);

    &.active {
      background: var(--card-bg);
      color: var(--text-primary);
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.06);
    }

    &:hover:not(.active) {
      color: var(--text-primary);
    }
  }

  /* Form fields */
  .field {
    margin-bottom: 16px;
  }

  .field label {
    display: block;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
    margin-bottom: 6px;
    transition: color 0.2s;
  }

  .input-wrapper {
    position: relative;
  }

  .input-wrapper input {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid var(--input-border);
    border-radius: 8px;
    font-size: 14px;
    font-family: inherit;
    background: var(--input-bg);
    color: var(--text-primary);
    outline: none;
    transition: all 0.15s;
    box-sizing: border-box;

    &::placeholder {
      color: var(--text-muted);
    }

    &:focus {
      border-color: var(--input-focus-border);
      box-shadow: 0 0 0 3px var(--input-focus-ring);
    }
  }

  .eye-toggle {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    padding: 2px;
    display: flex;
    align-items: center;
    border-radius: 4px;
    transition: color 0.15s;

    &:hover {
      color: var(--text-secondary);
    }
  }

  /* Primary button */
  .btn-primary {
    width: 100%;
    padding: 10px 16px;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    font-family: inherit;
    background: var(--btn-bg);
    color: var(--btn-text);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    transition: all 0.15s;
    margin-top: 4px;

    &:hover:not(:disabled) {
      background: var(--btn-bg-hover);
    }

    &:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }
  }

  :global(.spinner) {
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  /* Divider */
  .divider {
    display: flex;
    align-items: center;
    margin: 20px 0;
    gap: 12px;

    &::before,
    &::after {
      content: "";
      flex: 1;
      height: 1px;
      background: var(--divider);
    }

    span {
      font-size: 12px;
      color: var(--text-muted);
      text-transform: lowercase;
    }
  }

  /* OAuth buttons */
  .oauth-buttons {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .btn-oauth {
    width: 100%;
    padding: 10px 16px;
    border: 1px solid var(--oauth-border);
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    font-family: inherit;
    background: var(--oauth-bg);
    color: var(--oauth-text);
    cursor: pointer;
    transition: all 0.15s;

    &:hover {
      background: var(--oauth-hover);
      border-color: var(--input-focus-border);
    }
  }

  .card-header-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  .version {
    font-size: 11px;
    color: var(--text-muted);
    transition: color 0.2s;
    white-space: nowrap;
  }

  /* Error banner */
  .error-banner {
    margin-top: 16px;
    padding: 10px 14px;
    background: var(--error-bg);
    border-left: 3px solid var(--error-border);
    border-radius: 6px;
    font-size: 13px;
    color: var(--error-text);
    word-break: break-word;
    transition: all 0.2s;
  }
</style>
