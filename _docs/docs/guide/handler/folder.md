# Folder

Serves files from a directory. It can be used to serve static files or embed in your application.  
It supports SPA (Single Page Application) mode, directory browsing, index file serving, and cache control based on regex patterns, redirecting / for folder paths, redirect to index and stripping index file names from URLs.

```go
"github.com/rakunlabs/ada/handler/folder"
```

## Rule ordering

`FilePathRegex`, `CacheRegex` and `SPAIndexRegex` are ordered lists. Put more
specific rules before broad ones. `CacheRegex` stops at the first regex match;
the path rule lists stop at the first replacement that changes the path.

### `FilePathRegex` - rewritten at most once

The walk stops at the first rule whose replacement actually changes the path,
and the rewritten path is never fed back into the list. Rewrites therefore do
not chain:

```go
FilePathRegex: []*folder.RegexPathStore{
    {Regex: `^/start\.txt$`, Replacement: "/middle.txt"},
    {Regex: `^/middle\.txt$`, Replacement: "/final.txt"},
}
```

A request for `/start.txt` serves `middle.txt`, **not** `final.txt`.

A rule whose regex matches but whose replacement leaves the path identical does
not count as applied, so the walk continues to the next rule.

### `CacheRegex` - first match sets the header

Each regex is matched against the served file's **base name** (`index.html`),
not the request path. The first rule that matches sets `Cache-Control`; later
rules cannot add to or override it.

```go
CacheRegex: []*folder.RegexCacheStore{
    {Regex: `^app\.js$`, CacheControl: "no-cache"},                              // specific first
    {Regex: `.*\.(js|css)$`, CacheControl: "public, max-age=604800, immutable"}, // broad second
}
```

Swapping those two entries makes the `app.js` rule dead code.

### `SPAIndexRegex` - first rule that rewrites the path wins

The first rule whose replacement changes the request path selects the index file
to serve; the rest are skipped. If no rule changes the path, `SPAIndex` is
served.

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
