# Folder

Serves files from a directory on disk or from an embedded filesystem.

It supports:

- SPA (Single Page Application) mode
- Directory browsing and index file serving
- Cache control based on regex patterns
- Weak or strong `ETag` generation for conditional requests
- Redirecting folder paths to a trailing `/`, redirecting to the index, and stripping index file names from URLs

## Import

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

## ETag

`ETag` turns on `ETag` generation so clients can revalidate with
`If-None-Match` and get `304 Not Modified`. It is off by default.

| Value | ETag | Use for |
|---|---|---|
| `folder.ETagWeak` (`"weak"`) | `W/"<modtime>-<size>"`, computed without reading the file | Files on disk |
| `folder.ETagStrong` (`"strong"`) | `"<sha256 of content>"` | Embedded files, or when the exact content must be identified |

Embedded filesystems (`embed.FS`) have no modtime, so `http.ServeContent`
never sends `Last-Modified`; without `ETag: folder.ETagStrong` every request
downloads the full file again. Weak mode produces no ETag for such files.

Strong hashes are cached per file path and recomputed when the file's modtime
or size changes. With `SetCustomContent` the content may differ per request:
strong mode hashes it on every request and weak mode is skipped. An `ETag`
header already set by an earlier handler is kept. Any other value makes `New`
return an error.

When the [Encoding](../middleware/encoding) middleware compresses a response,
it weakens a strong ETag to `W/"…"`. `If-None-Match` uses weak comparison, so
`304` responses keep working.

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
    ETag:           folder.ETagStrong, // embedded files have no modtime
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
