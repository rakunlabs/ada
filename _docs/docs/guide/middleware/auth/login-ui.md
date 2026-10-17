# Login UI

The middleware ships an embedded Svelte login page that reads `/login/info` to dynamically render:

- Form inputs per strategy (username/password, email/token, etc.)
- OAuth2 redirect buttons
- Strategy tabs when multiple form strategies exist
- Optional "Sign up" toggle (per-strategy — appears only when the strategy has a `Registrar`)
- Light/dark theme toggle (persisted to `localStorage`, respects `prefers-color-scheme`)
- Runtime theme overrides (`UIConfig.Theme`) and custom stylesheet (`UIConfig.CustomCSSURL`)
- Configurable title, subtitle, icon, and version

## Styling the Built-in UI

Every color, radius, and surface in the login card reads a `--auth-*` CSS custom property. You can tune them without touching the Svelte source. Two knobs:

### Theme tokens (lightweight brand tweaks)

Pass a map of CSS variable overrides. Keys may be bare (`primary`, `btn-bg`) or fully qualified (`--auth-btn-bg`); the UI normalizes them to `--auth-*` custom properties on `:root`.

```go
authMW := auth.New(auth.Config{
    UI: auth.UIConfig{
        Theme: map[string]string{
            "btn-bg":              "#3b82f6",
            "btn-bg-hover":        "#2563eb",
            "input-focus-border":  "#3b82f6",
            "input-focus-ring":    "rgba(59, 130, 246, 0.18)",
        },
    },
})
```

**Radius scale** — three tokens cover every rounded corner, so you can make everything sharp, pill-shaped, or in between:

```go
Theme: map[string]string{
    "radius-lg": "0",    // the card
    "radius":    "0",    // inputs, primary button, OAuth buttons
    "radius-sm": "0",    // tabs, banners, theme toggle
}
```

**Full token list** (also documented at the top of `_ui/src/style/global.css`):

| Category | Tokens |
|---|---|
| Surfaces | `--auth-bg`, `--auth-card-bg`, `--auth-card-border`, `--auth-card-shadow` |
| Radii | `--auth-radius-sm`, `--auth-radius`, `--auth-radius-lg` |
| Text | `--auth-text-primary`, `--auth-text-secondary`, `--auth-text-muted` |
| Inputs | `--auth-input-bg`, `--auth-input-border`, `--auth-input-focus-border`, `--auth-input-focus-ring` |
| Primary button | `--auth-btn-bg`, `--auth-btn-bg-hover`, `--auth-btn-text` |
| OAuth buttons | `--auth-oauth-bg`, `--auth-oauth-border`, `--auth-oauth-hover`, `--auth-oauth-text` |
| Misc | `--auth-divider`, `--auth-toggle-bg`, `--auth-toggle-text`, `--auth-toggle-hover` |
| Error banner | `--auth-error-bg`, `--auth-error-border`, `--auth-error-text` |
| Notice banner | `--auth-notice-bg`, `--auth-notice-border`, `--auth-notice-text` |

Dark-mode overrides apply automatically from `[data-theme="dark"]`. If you need different values per mode, use the [custom stylesheet](#custom-stylesheet-full-control) escape hatch.

### Custom stylesheet (full control)

Point `CustomCSSURL` at a stylesheet your app serves; the UI appends it to `<head>` on load so your rules win the cascade.

```go
UI: auth.UIConfig{
    CustomCSSURL: "/static/auth.css",
}
```

Example `auth.css` — override dark-mode only:

```css
[data-theme="dark"] {
  --auth-bg: #0b1220;
  --auth-card-bg: #111a2c;
  --auth-btn-bg: #22d3ee;
}
```

You can also rewrite anything else — the custom CSS loads last and has full access to the card's class names (`.card`, `.btn-primary`, `.btn-oauth`, `.field`, `.strategy-tab`, `.notice-banner`, `.error-banner`, etc.).

::: info
The UI serves at `/login/` and its CSS loads before `/login/info` returns, so there's a brief flash of default styling before your `Theme` overrides apply. For fully flicker-free branding, use `CustomCSSURL` pointing at a file that hard-codes your values.
:::

## Custom Login Page

Set `ExternalFolder: true` and mount your own handler:

```go
authMW := auth.New(auth.Config{
    UI: auth.UIConfig{ExternalFolder: true},
})

// After authMW.Mount(mux):
mux.GET("/login/", myCustomLoginHandler)
```

Your page should fetch `./info` (relative to the login path) to get strategy descriptors and render matching forms/buttons.
