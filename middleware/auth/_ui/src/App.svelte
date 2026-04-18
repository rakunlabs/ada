<script lang="ts">
  import { formToObject } from "./helper/form";
  import { login, register, LoginError } from "./helper/login";
  import { getRedirectPath, isResponseTypeCode } from "./helper/query";
  import { initTheme, toggleTheme, getTheme } from "./helper/theme";
  import { applyThemeVars, appendCustomStylesheet } from "./helper/customize";
  import type { AuthInfo, StrategyDescriptor } from "./helper/info";
  import { Sun, Moon, Eye, EyeOff, Loader2 } from "lucide-svelte";

  let error = $state("");
  let notice = $state("");
  let working = $state(false);
  let mounted = $state(false);
  let showPassword = $state(false);
  let isDark = $state(false);
  let mode = $state<"login" | "register">("login");

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

  let anySignupAvailable = $derived(
    formStrategies.some((s) => !!s.register),
  );

  let signupAvailableForActive = $derived(!!activeForm?.register);

  let visibleFields = $derived(
    mode === "register" && activeForm?.register?.fields?.length
      ? activeForm.register.fields
      : activeForm?.fields ?? [],
  );

  const switchMode = (next: "login" | "register") => {
    if (mode === next) return;
    mode = next;
    error = "";
    notice = "";
  };

  const handleThemeToggle = () => {
    const next = toggleTheme();
    isDark = next === "dark";
  };

  const validateRegister = (data: Record<string, any>): string | null => {
    const password = data["password"];
    const confirm = data["password_confirm"];
    if (password !== undefined && confirm !== undefined && password !== confirm) {
      return "Passwords do not match";
    }
    return null;
  };

  const submit = async (
    e: SubmitEvent & { currentTarget: EventTarget & HTMLFormElement },
  ) => {
    e.preventDefault();
    e.stopPropagation();
    if (working || !activeForm) return;

    error = "";
    notice = "";
    const data = formToObject(e.currentTarget);

    if (mode === "register") {
      const problem = validateRegister(data);
      if (problem) {
        error = problem;
        return;
      }
      delete data["password_confirm"];
    }

    working = true;

    try {
      if (mode === "login") {
        await login(activeForm.url, data);

        if (!isResponseTypeCode()) {
          window.location.assign(getRedirectPath());
          return;
        }
        window.location.replace(window.location.href);
        return;
      }

      if (!activeForm.register) return;
      const result = await register(activeForm.register.url, data);

      if (result.auto_login) {
        if (!isResponseTypeCode()) {
          window.location.assign(result.redirect_path || getRedirectPath());
          return;
        }
        window.location.replace(window.location.href);
        return;
      }

      notice = "Account created. Please sign in.";
      e.currentTarget.reset();
      mode = "login";
    } catch (reason: unknown) {
      if (reason instanceof LoginError) {
        if (reason.status === 401) {
          error = "Invalid username or password";
        } else if (reason.status === 409) {
          error = reason.message || "Username already taken";
        } else {
          error = reason.message;
        }
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

      // Apply server-provided theme overrides + optional custom stylesheet
      // before revealing the card to minimize FOUC.
      if (authInfo.theme) applyThemeVars(authInfo.theme);
      if (authInfo.custom_css_url) appendCustomStylesheet(authInfo.custom_css_url);

      const title = new URLSearchParams(window.location.search).get("title");
      if (title) authInfo.title = title;

      document.title = authInfo.title;

      if (authInfo.signup_first) {
        queueMicrotask(() => {
          const first = formStrategies.find((s) => !!s.register);
          if (first) {
            selectedFormStrategy = first.name;
            mode = "register";
          }
        });
      }

      mounted = true;
    })();
  });
</script>

<div class="page">
  <div class="container">
    <div class="card">
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
            <h1 class="title" class:invisible={!mounted}>
              {mode === "register" ? "Create account" : authInfo.title}
            </h1>
            {#if authInfo.subtitle && mode === "login"}
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
                  notice = "";
                  if (mode === "register" && !s.register) mode = "login";
                }}
              >
                {s.label}
              </button>
            {/each}
          </div>
        {/if}

        {#if activeForm}
          <form onsubmit={submit}>
            {#each visibleFields as field (field.name)}
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
                    autocomplete={(field.type === "password"
                      ? mode === "register"
                        ? "new-password"
                        : "current-password"
                      : field.name) as any}
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
              {mode === "register" ? "Create account" : "Sign in"}
            </button>
          </form>

          {#if signupAvailableForActive || (mode === "register" && anySignupAvailable)}
            <div class="mode-toggle">
              {#if mode === "login"}
                <span>Don't have an account?</span>
                <button type="button" class="link" onclick={() => switchMode("register")}>
                  Sign up
                </button>
              {:else}
                <span>Already have an account?</span>
                <button type="button" class="link" onclick={() => switchMode("login")}>
                  Sign in
                </button>
              {/if}
            </div>
          {/if}
        {/if}
      {/if}

      {#if redirectStrategies.length && mode === "login"}
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

      {#if notice}
        <div class="notice-banner">
          <span>{notice}</span>
        </div>
      {/if}

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
    color: var(--auth-text-primary);
    margin: 0 0 4px;
    transition: color 0.2s;
  }

  .subtitle {
    font-size: 14px;
    color: var(--auth-text-muted);
    margin: 0;
    transition: color 0.2s;
  }

  .theme-toggle-inline {
    flex-shrink: 0;
    width: 32px;
    height: 32px;
    border-radius: var(--auth-radius-sm);
    border: 1px solid var(--auth-card-border);
    background: var(--auth-toggle-bg);
    color: var(--auth-toggle-text);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: all 0.15s;
    margin-top: 2px;

    &:hover {
      background: var(--auth-toggle-hover);
    }
  }

  .invisible {
    visibility: hidden;
  }

  .card {
    width: 100%;
    background: var(--auth-card-bg);
    border: 1px solid var(--auth-card-border);
    border-radius: var(--auth-radius-lg);
    padding: 28px;
    box-shadow: var(--auth-card-shadow);
    transition: all 0.2s;
  }

  .strategy-selector {
    display: flex;
    gap: 4px;
    background: var(--auth-bg);
    border-radius: var(--auth-radius);
    padding: 3px;
    margin-bottom: 20px;
  }

  .strategy-tab {
    flex: 1;
    padding: 7px 12px;
    border: none;
    border-radius: var(--auth-radius-sm);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
    background: transparent;
    color: var(--auth-text-secondary);

    &.active {
      background: var(--auth-card-bg);
      color: var(--auth-text-primary);
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.06);
    }

    &:hover:not(.active) {
      color: var(--auth-text-primary);
    }
  }

  .field {
    margin-bottom: 16px;
  }

  .field label {
    display: block;
    font-size: 13px;
    font-weight: 500;
    color: var(--auth-text-secondary);
    margin-bottom: 6px;
    transition: color 0.2s;
  }

  .input-wrapper {
    position: relative;
  }

  .input-wrapper input {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid var(--auth-input-border);
    border-radius: var(--auth-radius);
    font-size: 14px;
    font-family: inherit;
    background: var(--auth-input-bg);
    color: var(--auth-text-primary);
    outline: none;
    transition: all 0.15s;
    box-sizing: border-box;

    &::placeholder {
      color: var(--auth-text-muted);
    }

    &:focus {
      border-color: var(--auth-input-focus-border);
      box-shadow: 0 0 0 3px var(--auth-input-focus-ring);
    }
  }

  .eye-toggle {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: var(--auth-text-muted);
    cursor: pointer;
    padding: 2px;
    display: flex;
    align-items: center;
    border-radius: 4px;
    transition: color 0.15s;

    &:hover {
      color: var(--auth-text-secondary);
    }
  }

  .btn-primary {
    width: 100%;
    padding: 10px 16px;
    border: none;
    border-radius: var(--auth-radius);
    font-size: 14px;
    font-weight: 600;
    font-family: inherit;
    background: var(--auth-btn-bg);
    color: var(--auth-btn-text);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    transition: all 0.15s;
    margin-top: 4px;

    &:hover:not(:disabled) {
      background: var(--auth-btn-bg-hover);
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
      background: var(--auth-divider);
    }

    span {
      font-size: 12px;
      color: var(--auth-text-muted);
      text-transform: lowercase;
    }
  }

  .oauth-buttons {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .btn-oauth {
    width: 100%;
    padding: 10px 16px;
    border: 1px solid var(--auth-oauth-border);
    border-radius: var(--auth-radius);
    font-size: 14px;
    font-weight: 500;
    font-family: inherit;
    background: var(--auth-oauth-bg);
    color: var(--auth-oauth-text);
    cursor: pointer;
    transition: all 0.15s;

    &:hover {
      background: var(--auth-oauth-hover);
      border-color: var(--auth-input-focus-border);
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
    color: var(--auth-text-muted);
    transition: color 0.2s;
    white-space: nowrap;
  }

  .mode-toggle {
    text-align: center;
    margin-top: 16px;
    font-size: 13px;
    color: var(--auth-text-muted);
  }

  .link {
    background: none;
    border: none;
    padding: 0 0 0 4px;
    color: var(--auth-btn-bg);
    font: inherit;
    cursor: pointer;
    text-decoration: underline;

    &:hover {
      color: var(--auth-btn-bg-hover);
    }
  }

  .notice-banner {
    margin-top: 16px;
    padding: 10px 14px;
    background: var(--auth-notice-bg);
    border-left: 3px solid var(--auth-notice-border);
    border-radius: var(--auth-radius-sm);
    font-size: 13px;
    color: var(--auth-notice-text);
    word-break: break-word;
    transition: all 0.2s;
  }

  .error-banner {
    margin-top: 16px;
    padding: 10px 14px;
    background: var(--auth-error-bg);
    border-left: 3px solid var(--auth-error-border);
    border-radius: var(--auth-radius-sm);
    font-size: 13px;
    color: var(--auth-error-text);
    word-break: break-word;
    transition: all 0.2s;
  }
</style>
