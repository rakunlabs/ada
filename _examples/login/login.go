package login

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/session"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
	authoauth2 "github.com/rakunlabs/ada/middleware/auth/strategy/oauth2"
)

// Run wires the auth middleware with a local strategy and (optionally) an
// OAuth2 strategy, then mounts /dashboard and /me behind Require().
//
// Local users are seeded in users.go. OAuth2 is configured from env vars:
//
//	AUTH_OAUTH2_NAME           e.g. "google" or "keycloak" (default disabled)
//	AUTH_OAUTH2_LABEL          shown on the login page; defaults to NAME
//	AUTH_OAUTH2_CLIENT_ID
//	AUTH_OAUTH2_CLIENT_SECRET
//	AUTH_OAUTH2_AUTH_URL
//	AUTH_OAUTH2_TOKEN_URL
//	AUTH_OAUTH2_USERINFO_URL   optional
//	AUTH_OAUTH2_REVOCATION_URL optional
//	AUTH_OAUTH2_SCOPES         space-separated; default "openid email profile"
//
// Without AUTH_OAUTH2_NAME set, the OAuth2 strategy is skipped and the demo
// runs offline with just the local strategy.
func Run(ctx context.Context) error {
	authMW := auth.New(auth.Config{
		UI: auth.UIConfig{
			Title:    "ADA Login Demo",
			Subtitle: "Sign in to access the dashboard",
			Icon:     `data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2024%2024%22%3E%0A%20%20%3Cpolygon%20points%3D%2222.39%2C6.00%2022.39%2C18.00%2012.00%2C24.00%201.61%2C18.00%201.61%2C6.00%2012.00%2C0.00%22%20fill%3D%22%233b82f6%22%2F%3E%0A%20%20%3Csvg%20x%3D%224.199999999999999%22%20y%3D%224.199999999999999%22%20width%3D%2215.600000000000001%22%20height%3D%2215.600000000000001%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%23ffffff%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22M2%209.5a5.5%205.5%200%200%201%209.591-3.676.56.56%200%200%200%20.818%200A5.49%205.49%200%200%201%2022%209.5c0%202.29-1.5%204-3%205.5l-5.492%205.313a2%202%200%200%201-3%20.019L5%2015c-1.5-1.5-3-3.2-3-5.5%22%2F%3E%3C%2Fsvg%3E%0A%3C%2Fsvg%3E`,
			Version:  "v0.1.0",
		},
		Cookie: sessionCookieDefaults(),
	})

	authMW.Strategy(local.New("local",
		LocalVerifier,
		local.WithLabel("Email & password"),
	))

	authMW.Strategy(local.New("local2",
		LocalVerifier,
		local.WithLabel("Email & password"),
	))

	if oauth2Strategy := buildOAuth2FromEnv(); oauth2Strategy != nil {
		authMW.Strategy(oauth2Strategy)
		slog.Info("oauth2 strategy enabled", "name", oauth2Strategy.Name())
	} else {
		slog.Info("oauth2 strategy disabled (set AUTH_OAUTH2_NAME to enable)")
	}

	if err := authMW.Init(ctx); err != nil {
		return fmt.Errorf("auth init: %w", err)
	}

	server, err := ada.NewWithFunc(ctx, func(ctx context.Context, mux *ada.Mux) error {
		// Public auth routes + the inline login page handler at /auth/.
		authMW.Mount(mux)
		// mux.GET("/auth/", serveLoginPage)

		// Public landing.
		mux.GET("/", landingHandler)

		// Protected area.
		app := mux.Group("/app")
		app.Use(authMW.Require())
		app.GET("/dashboard", dashboardHandler)
		app.GET("/me", meHandler)

		return nil
	})
	if err != nil {
		return err
	}

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	slog.Info("login demo running", "url", "http://localhost"+addr+"/")

	return server.StartWithContext(ctx, addr)
}

func sessionCookieDefaults() session.CookieOptions {
	return session.CookieOptions{
		Path:     "/",
		MaxAge:   60 * 60 * 24,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false, // demo runs over HTTP
	}
}

func buildOAuth2FromEnv() *authoauth2.Strategy {
	name := os.Getenv("AUTH_OAUTH2_NAME")
	if name == "" {
		return nil
	}

	cfg := authoauth2.Config{
		ClientID:      os.Getenv("AUTH_OAUTH2_CLIENT_ID"),
		ClientSecret:  os.Getenv("AUTH_OAUTH2_CLIENT_SECRET"),
		AuthURL:       os.Getenv("AUTH_OAUTH2_AUTH_URL"),
		TokenURL:      os.Getenv("AUTH_OAUTH2_TOKEN_URL"),
		UserInfoURL:   os.Getenv("AUTH_OAUTH2_USERINFO_URL"),
		RevocationURL: os.Getenv("AUTH_OAUTH2_REVOCATION_URL"),
	}

	scopes := os.Getenv("AUTH_OAUTH2_SCOPES")
	if scopes == "" {
		scopes = "openid email profile"
	}
	cfg.Scopes = strings.Fields(scopes)

	if cfg.ClientID == "" || cfg.AuthURL == "" || cfg.TokenURL == "" {
		slog.Warn("oauth2 partial config; skipping", "name", name)

		return nil
	}

	label := os.Getenv("AUTH_OAUTH2_LABEL")
	if label == "" {
		label = "Sign in with " + name
	}

	return authoauth2.New(name, cfg, authoauth2.Options{
		Label:            label,
		EmailVerifyCheck: true,
		CallbackBasePath: "/auth/callback",
	})
}

// landingHandler is the public homepage with a link to the login page.
func landingHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><meta charset=utf-8>
<title>ADA Login Demo</title>
<h1>ADA Login Demo</h1>
<ul>
  <li><a href="/login">Login</a></li>
  <li><a href="/app/dashboard">Dashboard (requires login)</a></li>
  <li><a href="/app/me">/app/me JSON (requires login)</a></li>
</ul>`))
}

// dashboardHandler renders a simple page using the live identity.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	id := identity.FromContext(r.Context())
	if id == nil {
		http.Error(w, "no identity", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = dashboardTmpl.Execute(w, id)
}

// meHandler returns the current Identity as JSON.
func meHandler(w http.ResponseWriter, r *http.Request) {
	id := identity.FromContext(r.Context())
	if id == nil {
		http.Error(w, "no identity", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = jsonEncode(w, id)
}

var dashboardTmpl = template.Must(template.New("dashboard").Parse(`<!doctype html><meta charset=utf-8>
<title>Dashboard</title>
<h1>Hello, {{or .Name .Email .Subject}}</h1>
<p>Provider: <code>{{.Provider}}</code></p>
<ul>
  <li><strong>subject</strong>: {{.Subject}}</li>
  <li><strong>email</strong>: {{.Email}} (verified: {{.EmailVerified}})</li>
  <li><strong>roles</strong>: {{range .Roles}}{{.}} {{end}}</li>
  <li><strong>scopes</strong>: {{range .Scopes}}{{.}} {{end}}</li>
</ul>
<form method="post" action="/auth/logout" onsubmit="event.preventDefault();fetch('/auth/logout',{method:'POST'}).then(()=>location.href='/')">
  <button type="submit">Log out</button>
</form>
`))

// serveLoginPage is a minimal inline login UI used because the demo runs in
// external-folder mode (no embedded Svelte build needed). It hits /auth/info
// to discover strategies and renders matching widgets.
func serveLoginPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(loginPageHTML))
}

const loginPageHTML = `<!doctype html><meta charset=utf-8>
<title>Login</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:380px;margin:60px auto;padding:0 16px}
 form{display:flex;flex-direction:column;gap:8px;margin:16px 0}
 input,button{padding:8px 12px;font:inherit;border:1px solid #ccc;border-radius:6px}
 button{cursor:pointer;background:#615fff;color:#fff;border-color:#615fff}
 .err{background:#fee;padding:8px;border-radius:6px;margin-top:8px}
 .oauth{display:block;text-align:center;background:#fff;color:#000;border:1px solid #ccc;padding:8px;border-radius:6px;margin-top:8px;text-decoration:none}
 hr{margin:16px 0;border:none;border-top:1px solid #eee}
</style>
<h1 id="title">Sign in</h1>
<div id="content">Loading...</div>
<div id="error" class="err" style="display:none"></div>
<script>
(async () => {
  const $c = document.getElementById('content');
  const $e = document.getElementById('error');
  const showErr = (msg) => { $e.textContent = msg; $e.style.display = 'block'; };

  let info;
  try {
    const r = await fetch('/login/info');
    info = await r.json();
  } catch (err) { return showErr('Failed to load /login/info: ' + err); }

  document.getElementById('title').textContent = info.title || 'Sign in';
  $c.innerHTML = '';

  const formStrategies = info.strategies.filter(s => (s.fields && s.fields.length) || s.kind === 'password');
  const redirectStrategies = info.strategies.filter(s => !(s.fields && s.fields.length) && s.kind !== 'password');

  for (const s of formStrategies) {
    const form = document.createElement('form');
    form.innerHTML = '<h3>' + s.label + '</h3>';
    for (const f of (s.fields || [])) {
      const input = document.createElement('input');
      input.name = f.name; input.type = f.type || 'text'; input.placeholder = f.label || f.name;
      input.required = !!f.required;
      form.appendChild(input);
    }
    const submit = document.createElement('button');
    submit.type = 'submit'; submit.textContent = 'Sign in';
    form.appendChild(submit);
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const data = {};
      new FormData(form).forEach((v, k) => { data[k] = v; });
      try {
        const r = await fetch(s.url, {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
          body: JSON.stringify(data),
        });
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          return showErr(body.message || body.error || ('Login failed: ' + r.status));
        }
        const params = new URLSearchParams(location.search);
        location.assign(params.get('redirect_path') || '/app/dashboard');
      } catch (err) { showErr(String(err)); }
    });
    $c.appendChild(form);
  }

  if (formStrategies.length && redirectStrategies.length) {
    $c.appendChild(document.createElement('hr'));
  }

  for (const s of redirectStrategies) {
    const a = document.createElement('a');
    a.className = 'oauth'; a.textContent = s.label; a.href = s.url + (location.search || '');
    $c.appendChild(a);
  }

  if (!info.strategies.length) {
    $c.textContent = 'No strategies configured.';
  }
})();
</script>`
