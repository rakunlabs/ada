# Configuration

## Auth Config

| Field | Type | Default | Description |
|---|---|---|---|
| `Base` | `string` | `"/"` | URL prefix for all auth routes |
| `UI.Title` | `string` | `"Sign in"` | Title shown on login page |
| `UI.Subtitle` | `string` | `""` | Text below the title |
| `UI.Icon` | `string` | `""` | Logo URL, data URI, inline SVG, or filename in embedded FS |
| `UI.Version` | `string` | `""` | Version text shown in header |
| `UI.ExternalFolder` | `bool` | `false` | Use your own login page instead of embedded UI |
| `UI.SignupFirst` | `bool` | `false` | Land on the signup form instead of login (first-run bootstrap) |
| `UI.Theme` | `map[string]string` | `nil` | CSS variable overrides applied to `:root` at load (e.g. `{"btn-bg": "#3b82f6"}`) |
| `UI.CustomCSSURL` | `string` | `""` | URL of a stylesheet appended to the login page for full restyling |
| `CookieName` | `string` | `"auth_session"` | Session cookie name |
| `Cookie.Path` | `string` | `"/"` | Cookie path |
| `Cookie.MaxAge` | `int` | `0` | Cookie max-age in seconds |
| `Cookie.Domain` | `string` | `""` | Cookie domain |
| `Cookie.Secure` | `cookie.SecureMode` | `auto` | `auto` (set when the request is HTTPS), `always`, or `never` |
| `Cookie.DisableHTTPOnly` | `bool` | `false` | Expose the cookie to JavaScript. **HttpOnly is on by default** |
| `Cookie.SameSite` | `http.SameSite` | `Lax` | Cookie SameSite policy |
| `IssuerConfig.AccessTTL` | `time.Duration` | `15m` | Access token lifetime, clamped to `RefreshTTL` |
| `IssuerConfig.RefreshTTL` | `time.Duration` | `7d` | Refresh token and maximum session lifetime |
| `IssuerConfig.DisableRefreshRotation` | `bool` | `false` | Turn off refresh rotation. **Rotation is on by default** |
| `MFA.CookieName` | `string` | `"auth_mfa"` | Pending-login cookie (only used with `WithSecondFactor`) |
| `MFA.TTL` | `time.Duration` | `5m` | How long the user has to complete the second factor |
| `MFA.MaxAttempts` | `int` | `5` | Wrong codes tolerated before the pending login is destroyed |
| `ProtectedResource` | `*resource.Config` | `nil` | Publish RFC 9728 metadata. See [Resource Server](./resource-server) |
| `DisableRequestAuth` | `bool` | `false` | Turn off request-credential auth in `Require()`, restoring cookie-only gating |

`Cookie.Secure` defaults to `auto`: the `Secure` attribute is set when the
request arrived over TLS, directly or via `X-Forwarded-Proto`. That protects
real deployments without breaking `http://localhost`. Pin it to `always` when
TLS terminates upstream and the proxy forwards no protocol hint.

## OAuth2 Config

| Field | Type | Default | Description |
|---|---|---|---|
| `IssuerURL` | `string` | `""` | OIDC issuer URL for auto-discovery |
| `ClientID` | `string` | required | OAuth2 client ID |
| `ClientSecret` | `string` | required | OAuth2 client secret |
| `Scopes` | `[]string` | `[]` | Requested scopes |
| `AuthURL` | `string` | auto | Authorization endpoint |
| `TokenURL` | `string` | auto | Token endpoint |
| `UserInfoURL` | `string` | auto | UserInfo endpoint |
| `RevocationURL` | `string` | auto | Token revocation endpoint |
| `LogoutURL` | `string` | auto | End-session endpoint |
| `JWKSURL` | `string` | auto | Key set used to verify the `id_token` signature |
| `Audience` | `string` | `ClientID` | Value required in the `id_token` `aud` claim |
| `ClockSkew` | `time.Duration` | `60s` | Tolerance applied to `exp` / `nbf` |
| `DisablePKCE` | `bool` | `false` | Disable PKCE (not recommended) |
| `DisableNonce` | `bool` | `false` | Omit the OIDC `nonce` (not recommended) |
| `SkipIDTokenVerify` | `bool` | `false` | Accept an unverified `id_token`. **Do not set this** |
| `PasswordFlow` | `bool` | `false` | Enable resource owner password flow |
| `AuthHeaderStyle` | `int` | `0` (Basic) | `0`=Basic, `1`=Bearer, `2`=Params |

## ID token verification

An `id_token`, when present, is always verified: RS/PS/ES/EdDSA signature
against the IdP's JWKS, then `iss`, `aud`, `exp`, `nbf` and `nonce`.

Claims are taken from `UserInfoURL` when it is configured, otherwise from the
verified `id_token`. With neither — no userinfo endpoint and no reachable key
set — the login **fails** rather than falling back to an unverified payload.
`SkipIDTokenVerify` exists for the single case of an IdP that publishes no key
set on a trusted channel; it turns the `id_token` into an unauthenticated
assertion of whatever the caller wants.

JWKS keys are cached. A successful fetch starts the normal one-minute refresh
cooldown used to prevent unknown-key requests from amplifying traffic to the
IdP. A failed fetch instead uses a bounded two-second retry backoff, so a brief
provider outage does not suppress retries for a full minute. Concurrent misses
share one refresh, while lookups of cached keys continue without waiting for
the IdP. JWKS requests use the caller or configured client timeout, with a
30-second fallback only when neither supplies a deadline. An ID token with no
`kid` is accepted only when the JWKS has exactly one usable key; with multiple
keys it fails immediately as ambiguous without another fetch.

State, nonce and the PKCE verifier live together in one `HttpOnly` cookie
(`auth_flow_<name>`), cleared after a single use. Override its attributes with
`Options.FlowCookie` if the callback lands on a different subdomain.

## Routes

With default `Base: "/"`:

| Method | Path | Description |
|---|---|---|
| GET | `/login/` | Login UI (embedded Svelte or external folder) |
| GET | `/login/info` | JSON: title, subtitle, icon, version, strategies |
| GET | `/login/me` | Current user's Identity as JSON |
| GET/POST | `/login/pass/{strategy}` | Initiate or submit login |
| POST | `/login/register/{strategy}` | Create an account (strategy must implement `Registerer`) |
| GET | `/login/callback/{strategy}` | OAuth2 redirect callback |
| POST | `/login/refresh` | Force-refresh access token |
| POST | `/login/mfa` | Complete a second factor (only with `WithSecondFactor`) |
| POST | `/logout` | Revoke session and clear cookie |
| GET | `/login/status` | Status iframe (for popup flow) |
| GET | `/.well-known/oauth-protected-resource[/…]` | RFC 9728 metadata, only when `ProtectedResource` is set. Mounted at the origin, not under `Base`, and never behind `Require()` |

### Request body limits

Auth endpoints enforce the following request-body caps:

| Request | Limit |
|---|---:|
| Local login and registration | 64 KiB |
| LDAP login | 64 KiB |
| Magic-link request | 64 KiB |
| OAuth2 password form | 64 KiB |
| TOTP second factor | 16 KiB |
| Passkey login begin or finish | 128 KiB |

An oversized body receives JSON `413 Content Too Large` with error code
`body_too_large`; its message includes the applicable byte limit. The body is
rejected before JSON or form parsing, so it is not misreported as malformed
input.

`POST /login/refresh` rotates the server-side token pair and returns
`{"identity": ...}`. It no longer returns `session_id`; the opaque session ID
remains confined to the `HttpOnly` cookie and clients must not expect it in the
JSON response.
