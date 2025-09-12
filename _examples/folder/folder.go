package folder

import (
	"context"
	"embed"
	"io/fs"
	"net/http"

	"github.com/rakunlabs/ada"

	"github.com/rakunlabs/ada/handler/folder"

	mcors "github.com/rakunlabs/ada/middleware/cors"
	mlog "github.com/rakunlabs/ada/middleware/log"
	mrecover "github.com/rakunlabs/ada/middleware/recover"
	mrequestid "github.com/rakunlabs/ada/middleware/requestid"
	mserver "github.com/rakunlabs/ada/middleware/server"
	mtelemetry "github.com/rakunlabs/ada/middleware/telemetry"
)

//go:embed dist/*
var uiFS embed.FS

func Run(ctx context.Context) error {
	server, err := ada.NewWithFunc(ctx, func(ctx context.Context, mux *ada.Mux) error {
		mux.Use(
			mrecover.Middleware(),
			mserver.Middleware("MyServer"),
			mrequestid.Middleware(),
			mlog.Middleware(),
			mcors.Middleware(),
			mtelemetry.Middleware(),
		)

		f, err := folder.New(&folder.Config{
			Browse:         false,
			SPA:            true,
			Index:          true,
			StripIndexName: true,
			// PrefixPath:     "/mypath",
			CacheRegex: []*folder.RegexCacheStore{
				{
					Regex:        `index\.html$`,
					CacheControl: "no-store",
				},
				{
					Regex:        `.*`,
					CacheControl: "no-cache",
				},
			},
		})
		if err != nil {
			return err
		}

		uiDist, err := fs.Sub(uiFS, "dist")
		if err != nil {
			return err
		}

		f.SetFs(http.FS(uiDist))

		mux.Handle("/*", f)

		return nil
	})
	if err != nil {
		return err
	}

	return server.StartWithContext(ctx, ":8080")
}
