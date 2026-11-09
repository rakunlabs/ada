package users

import (
	"embed"
	"html"
	"net/http"
	"strings"
)

//go:embed admin/index.html admin/admin.css admin/admin.js
var adminFS embed.FS

// UIOptions configures MountAdminUI.
type UIOptions struct {
	// API is the URL of MountAdmin's prefix. Required. A path relative to
	// the page ("../") keeps working behind a proxy that strips a prefix;
	// an absolute path ("/api/admin/users") does not.
	API string
	// AccountAPI is the URL of MountSelf's prefix; the page uses it to show
	// who is signed in and to hide actions they may not take. Relative
	// paths work as for API.
	AccountAPI string
	// Title replaces "Users" in the page heading.
	Title string
}

// MountAdminUI serves a small user-management page at prefix + "/". It is
// plain HTML and JavaScript over the MountAdmin API: list, filter, create,
// edit roles, reset passwords, disable and delete. mw must authenticate
// (and should redirect browsers to the login page); the page itself needs
// users:read.
func (s *Service) MountAdminUI(mux Mux, prefix string, opts UIOptions, mw ...func(http.Handler) http.Handler) {
	prefix = strings.TrimSuffix(prefix, "/")
	guarded := append(append([]func(http.Handler) http.Handler(nil), mw...), s.RequirePermission(PermUsersRead))

	index, _ := adminFS.ReadFile("admin/index.html")
	css, _ := adminFS.ReadFile("admin/admin.css")
	js, _ := adminFS.ReadFile("admin/admin.js")

	meta := `<meta name="ada-users-api" content="` + html.EscapeString(opts.API) + `">` +
		`<meta name="ada-account-api" content="` + html.EscapeString(opts.AccountAPI) + `">`
	page := strings.Replace(string(index), `<meta name="referrer" content="no-referrer">`, `<meta name="referrer" content="no-referrer">`+meta, 1)

	if opts.Title != "" {
		t := html.EscapeString(opts.Title)
		page = strings.Replace(page, "<title>Users</title>", "<title>"+t+"</title>", 1)
		page = strings.Replace(page, "<h1>Users</h1>", "<h1>"+t+"</h1>", 1)
	}

	serve := func(body []byte, contentType string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			h := w.Header()
			h.Set("Content-Type", contentType)
			h.Set("Cache-Control", "no-store")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
			_, _ = w.Write(body)
		}
	}

	// Relative, so a proxy that strips a path prefix still lands on the page.
	last := prefix[strings.LastIndexByte(prefix, '/')+1:]
	mux.HandleWithMethod(http.MethodGet, prefix, func(w http.ResponseWriter, r *http.Request) {
		target := last + "/"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}

		http.Redirect(w, r, target, http.StatusFound)
	})
	mux.HandleWithMethod(http.MethodGet, prefix+"/", serve([]byte(page), "text/html; charset=utf-8"), guarded...)
	mux.HandleWithMethod(http.MethodGet, prefix+"/admin.css", serve(css, "text/css; charset=utf-8"))
	mux.HandleWithMethod(http.MethodGet, prefix+"/admin.js", serve(js, "text/javascript; charset=utf-8"))
}
