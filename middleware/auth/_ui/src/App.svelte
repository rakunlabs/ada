<script lang="ts">
  import { formToObject } from "./helper/form";
  import { login, register, LoginError } from "./helper/login";
  import { getRedirectPath, isResponseTypeCode } from "./helper/query";
  import { initTheme, toggleTheme, getTheme } from "./helper/theme";
  import { applyThemeVars, appendCustomStylesheet } from "./helper/customize";
  import {
    isWebAuthnSupported,
    isConditionalMediationAvailable,
    startAuthentication,
    type ServerRequestOptions,
  } from "./helper/webauthn";
  import type { AuthInfo, StrategyDescriptor } from "./helper/info";
  import { Sun, Moon, Eye, EyeOff, Loader2, KeyRound } from "lucide-svelte";
  import { onDestroy } from "svelte";

  let error = $state("");
  let notice = $state("");
  let working = $state(false);
  let mounted = $state(false);
  let showPasswordFields: Record<string, boolean> = $state({});
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

  // Passkey strategies live in their own bucket because they neither
  // render a form (no fields) nor follow the OAuth popup flow. Their
  // login URL points at the same /login/pass/<name> endpoint password
  // strategies use, but the wire shape is two POSTs sandwiching a
  // navigator.credentials.get() call.
  let passkeyStrategies = $derived(
    authInfo.strategies.filter((s) => s.kind === "passkey"),
  );

  let redirectStrategies = $derived(
    authInfo.strategies.filter(
      (s) =>
        (s.fields?.length ?? 0) === 0
        && s.kind !== "password"
        && s.kind !== "passkey",
    ),
  );

  // Feature flags for the passkey affordance. webauthnSupported is a
  // one-shot detection done at mount; conditionalSupported is the
  // separate, async check for the autofill UI. We only kick off the
  // conditional ceremony when both are true and the server advertises
  // at least one passkey strategy.
  let webauthnSupported = $state(false);
  let conditionalSupported = $state(false);
  let conditionalController: AbortController | null = null;

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

    // Tearing down the conditional passkey ceremony here means that
    // submitting the password form (or any non-passkey login) doesn't
    // race a stale autofill resolve.
    conditionalController?.abort();
    conditionalController = null;

    const form = e.currentTarget;
    error = "";
    notice = "";
    const data = formToObject(form);

    if (mode === "register") {
      const problem = validateRegister(data);
      if (problem) {
        error = problem;
        return;
      }
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
      form.reset();
      mode = "login";
    } catch (reason: unknown) {
      if (reason instanceof LoginError) {
        if (reason.status === 401) {
          error = "Invalid username or password";
        } else if (reason.status === 409) {
          // First user already created — reload to get updated info
          // (signup_first will be false now, showing the login form).
          window.location.reload();
          return;
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

  // Passkey login: two-step ceremony against the same /login/pass/<name>
  // endpoint password strategies use. The first POST sends an empty
  // body and gets back { phase: "begin", session_id, options }; the
  // browser ceremony produces an assertion; the second POST sends
  // { session_id, assertion } which the strategy dispatches to its
  // finish handler. We never POST a form to that URL ourselves.
  const handlePasskeyLogin = async (strategy: StrategyDescriptor) => {
    if (!webauthnSupported) {
      error = "Your browser does not support passkeys.";
      return;
    }
    // A click on the manual button overrides any in-flight conditional
    // ceremony — letting both run would race in some browsers.
    conditionalController?.abort();
    conditionalController = null;

    error = "";
    notice = "";
    working = true;
    try {
      const begin = await login(strategy.url, {});
      const sessionID: string = begin.session_id;
      const options: ServerRequestOptions = begin.options;

      const assertion = await startAuthentication(options);
      if (!assertion) {
        // User dismissed the picker. Silent — no error banner.
        return;
      }

      await login(strategy.url, { session_id: sessionID, assertion });

      if (!isResponseTypeCode()) {
        window.location.assign(getRedirectPath());
        return;
      }
      window.location.replace(window.location.href);
    } catch (reason: unknown) {
      if (reason && typeof reason === "object" && (reason as { name?: string }).name === "NotAllowedError") {
        // User cancelled the platform prompt — silent.
        return;
      }
      if (reason instanceof LoginError) {
        error = reason.message;
      } else if (reason instanceof Error) {
        error = reason.message;
      } else {
        error = String(reason);
      }
    } finally {
      working = false;
    }
  };

  // Conditional ("autofill") passkey login. Kicks off in the
  // background once mount completes, hangs on a get() promise the
  // browser surfaces via the username autofill dropdown. Picking a
  // passkey resolves it; typing a password and submitting the form
  // aborts it via conditionalController.
  //
  // Every failure path is silent: conditional UI is a progressive
  // enhancement and must never block the manual flows on the page.
  const tryConditionalAuth = async (strategy: StrategyDescriptor) => {
    if (!webauthnSupported) return;
    if (!(await isConditionalMediationAvailable())) return;
    conditionalSupported = true;

    conditionalController?.abort();
    conditionalController = new AbortController();
    const signal = conditionalController.signal;

    try {
      const begin = await login(strategy.url, {});
      if (signal.aborted) return;

      const sessionID: string = begin.session_id;
      const options: ServerRequestOptions = begin.options;
      const assertion = await startAuthentication(options, {
        mediation: "conditional",
        signal,
      });
      if (!assertion || signal.aborted) return;

      await login(strategy.url, { session_id: sessionID, assertion });
      if (!isResponseTypeCode()) {
        window.location.assign(getRedirectPath());
        return;
      }
      window.location.replace(window.location.href);
    } catch {
      // Conditional UI must never pre-empt the manual paths.
    }
  };

  onDestroy(() => {
    conditionalController?.abort();
    conditionalController = null;
  });

  $effect(() => {
    initTheme();
    isDark = getTheme() === "dark";
    webauthnSupported = isWebAuthnSupported();

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

      // Fire-and-forget the conditional passkey ceremony so the
      // browser's autofill dropdown can surface enrolled passkeys
      // as soon as the user focuses the username field. We pick
      // the first passkey strategy when several are advertised;
      // simultaneously running more than one conditional get()
      // is undefined-behavior across browsers.
      const passkey = passkeyStrategies[0];
      if (passkey) {
        void tryConditionalAuth(passkey);
      }
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
                      ? showPasswordFields[field.name]
                        ? "text"
                        : "password"
                      : field.type}
                    required={field.required}
                    placeholder={field.placeholder ?? ""}
                    autocomplete={
                      // Append "webauthn" to the username/email hint
                      // when a passkey strategy is present and the
                      // browser supports conditional UI — this is
                      // what makes enrolled passkeys appear in the
                      // username field's autofill dropdown.
                      (field.type === "password"
                        ? mode === "register"
                          ? "new-password"
                          : "current-password"
                        : passkeyStrategies.length > 0
                          && conditionalSupported
                          && (field.name === "username"
                            || field.name === "email"
                            || field.name === "user")
                          ? "username webauthn"
                          : field.name) as any
                    }
                  />
                  {#if field.type === "password"}
                    <button
                      type="button"
                      class="eye-toggle"
                      onclick={() => (showPasswordFields[field.name] = !showPasswordFields[field.name])}
                      aria-label={showPasswordFields[field.name]
                        ? "Hide password"
                        : "Show password"}
                    >
                      {#if showPasswordFields[field.name]}
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

      {#if (redirectStrategies.length || passkeyStrategies.length) && mode === "login"}
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

          {#each passkeyStrategies as s}
            <button
              type="button"
              class="btn-passkey"
              onclick={() => handlePasskeyLogin(s)}
              disabled={working || !webauthnSupported}
              title={webauthnSupported
                ? undefined
                : "Your browser does not support passkeys"}
            >
              <KeyRound size={16} />
              <span>{s.label}</span>
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

  /* Passkey button: shares the OAuth row's chrome so the visual
     rhythm of the "or" column stays uniform, but its icon makes
     the kind of credential explicit. Disabled state covers the
     "browser does not support WebAuthn" fallback. */
  .btn-passkey {
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
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;

    &:hover:not(:disabled) {
      background: var(--auth-oauth-hover);
      border-color: var(--auth-input-focus-border);
    }

    &:disabled {
      opacity: 0.5;
      cursor: not-allowed;
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
