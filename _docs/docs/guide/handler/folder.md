# Folder

Serves files from a directory. It can be used to serve static files or embed in your application.  
It supports SPA (Single Page Application) mode, directory browsing, index file serving, and cache control based on regex patterns, redirecting / for folder paths, redirect to index and stripping index file names from URLs.

```go
"github.com/rakunlabs/ada/handler/folder"
```

## Example

### Serving static files from a directory

```go
f, err := folder.New(&folder.Config{
    Browse:         false,
    SPA:            false,
    Index:          true,
    StripIndexName: true,
    Path:          "./dist",
    // PrefixPath:     "/mypath",
    CacheRegex: []*folder.RegexCacheStore{
        {
            Regex:        `index\.html$`,
            CacheControl: "no-cache",
        },
    },
})
if err != nil {
    return err
}

mux.Handle("/*", f)
```

### Browsing enabled

Need to import the browser subpackage which adds extra dependencies for directory browsing.

```go
_ "github.com/rakunlabs/ada/handler/folder/browser"
```

```go
f, err := folder.New(&folder.Config{
    Browse:         true,
    Path:          "./dist",
})
```

### Embedding files

You can embed files using Go's `embed` package.

```go
//go:embed dist/*
var uiFS embed.FS
```

Get folder's handler

```go
f, err := folder.New(&folder.Config{
    PrefixPath:     pathPrefix,
    Browse:         false,
    SPA:            false,
    Index:          true,
    StripIndexName: true,
    CacheRegex: []*folder.RegexCacheStore{
        {
            Regex:        `index\.html$`,
            CacheControl: "no-cache",
        },
        {
            Regex:        `.*\.(js|css|wasm|svg)$`,
            CacheControl: "public, max-age=604800, immutable", // 7 days
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
```
