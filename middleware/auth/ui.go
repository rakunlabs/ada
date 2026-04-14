package auth

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/rakunlabs/ada/handler/folder"
)

//go:embed _ui/dist/*
var uiFS embed.FS

// uiHandler serves the embedded Svelte login UI (or a no-op when external
// folder mode is enabled).
type uiHandler struct {
	handler http.Handler
}

func newUIHandler(cfg Config) (*uiHandler, error) {
	if cfg.UI.ExternalFolder {
		return &uiHandler{}, nil
	}

	sub, err := fs.Sub(uiFS, "_ui/dist")
	if err != nil {
		return nil, err
	}

	folderHandler, err := folder.New(&folder.Config{
		Index:          true,
		StripIndexName: true,
		SPA:            true,
		Browse:         false,
		PrefixPath:     cfg.Base + "login",
		CacheRegex: []*folder.RegexCacheStore{
			{Regex: `index\.html$`, CacheControl: "no-store"},
			{Regex: `.*`, CacheControl: "public, max-age=259200"},
		},
	})
	if err != nil {
		return nil, err
	}

	folderHandler.SetFs(http.FS(sub))

	return &uiHandler{handler: folderHandler}, nil
}

func (u *uiHandler) serve(w http.ResponseWriter, r *http.Request) {
	if u.handler == nil {
		http.NotFound(w, r)

		return
	}

	u.handler.ServeHTTP(w, r)
}
