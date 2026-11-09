package oauthserver

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
)

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{if .Error}}Authorization failed{{else}}Authorize {{.Client}}{{end}}</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--fg:#1c1f24;--muted:#646b75;--line:#e3e6ea;--primary:#2f6fed;--primary-fg:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#111316;--card:#1a1d21;--fg:#e8eaed;--muted:#9aa1ab;--line:#2c3036;--primary:#5b8cff}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px}
main{width:100%;max-width:420px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px}
h1{font-size:19px;margin:0 0 6px}
p{margin:0 0 14px;color:var(--muted)}
strong{color:var(--fg)}
ul{margin:0 0 18px;padding:0;list-style:none;border:1px solid var(--line);border-radius:8px}
li{padding:8px 12px;border-top:1px solid var(--line);font-family:ui-monospace,monospace;font-size:13px}
li:first-child{border-top:0}
.who{font-size:13px;margin-bottom:18px}
.redirect{font-size:12px;word-break:break-all}
label{display:flex;gap:8px;align-items:center;margin:0 0 18px;font-size:14px}
.actions{display:flex;gap:10px}
button{flex:1;padding:10px 14px;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--fg);font:inherit;cursor:pointer}
button.primary{background:var(--primary);border-color:var(--primary);color:var(--primary-fg)}
</style>
</head>
<body>
<main>
{{if .Error}}
<h1>Authorization failed</h1>
<p>{{.Error}}</p>
{{else}}
<h1>Authorize {{.Client}}</h1>
<p><strong>{{.Client}}</strong> wants to access <strong>{{.Service}}</strong> on your behalf.</p>
{{if .Scopes}}<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Resource}}<p class="redirect">Resource: {{.Resource}}</p>{{end}}
{{if .User}}<p class="who">Signed in as <strong>{{.User}}</strong></p>{{end}}
<form method="post" action="{{.Action}}">
{{range $k, $v := .Fields}}<input type="hidden" name="{{$k}}" value="{{$v}}">
{{end}}<input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .CanRemember}}<label><input type="checkbox" name="remember" value="1"> Don't ask again for this application</label>{{end}}
<div class="actions">
<button type="submit" name="action" value="deny">Deny</button>
<button type="submit" name="action" value="approve" class="primary">Allow</button>
</div>
</form>
<p class="redirect">You will be sent to {{.RedirectHost}}</p>
{{end}}
</main>
</body>
</html>
`))

type pageData struct {
	Error        string
	Client       string
	Service      string
	Scopes       []string
	Resource     string
	User         string
	Action       string
	Fields       map[string]string
	CSRF         string
	CanRemember  bool
	RedirectHost string
}

func writePage(w http.ResponseWriter, status int, data pageData) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	// The page must not be framed: a consent button under somebody else's
	// overlay is a click-jacked grant. form-action is left out on purpose:
	// browsers apply it to the redirect after the POST, and the client's
	// redirect URI may be a loopback port or an app scheme.
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)

	if err := pageTemplate.Execute(w, data); err != nil {
		slog.Debug("oauthserver: render page", "error", err.Error())
	}
}

func (s *Server) renderError(w http.ResponseWriter, status int, msg string) {
	writePage(w, status, pageData{Error: msg})
}

func (s *Server) renderConsent(w http.ResponseWriter, r *http.Request, req *AuthorizeRequest, csrf string) {
	fields := map[string]string{}
	for k, v := range paramsOf(r.URL.Query()).values() {
		fields[k] = v[0]
	}

	user := req.Identity.Email
	if user == "" {
		user = req.Identity.Name
	}
	if user == "" {
		user = req.Identity.Subject
	}

	redirectHost := req.RedirectURI
	if u, err := url.Parse(req.RedirectURI); err == nil {
		if u.Host != "" {
			redirectHost = u.Scheme + "://" + u.Host
		} else {
			redirectHost = u.Scheme + ":"
		}
	}

	_, canRemember := s.store.(ConsentStore)

	writePage(w, http.StatusOK, pageData{
		Client:       req.Client.Name,
		Service:      s.serviceName(r),
		Scopes:       req.Scopes,
		Resource:     req.Resource,
		User:         user,
		Action:       s.publicURL(r, s.Paths().Authorize),
		Fields:       fields,
		CSRF:         csrf,
		CanRemember:  canRemember,
		RedirectHost: redirectHost,
	})
}
