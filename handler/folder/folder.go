package folder

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

const indexPage = "/index.html"

const (
	// ETagWeak generates W/"<modtime>-<size>" without reading the file.
	ETagWeak = "weak"
	// ETagStrong generates a SHA-256 of the content and works without modtime.
	ETagStrong = "strong"
)

var BrowserFunc func(w http.ResponseWriter, r *http.Request, opt BrowserOption) error

type BrowserOption struct {
	UTC         bool
	BasePath    string
	Folder      http.File
	BrowseCache string
}

type Config struct {
	// BasePath for better UI browser expriance and not show .. if already in base path
	BasePath string `cfg:"base_path"`
	// Path is the path to the folder
	Path string `cfg:"path"`
	// Index is automatically redirect to index.html
	Index bool `cfg:"index"`
	// StripIndexName is strip index name from url
	StripIndexName bool `cfg:"strip_index_name"`
	// IndexName is the name of the index file, default is index.html
	IndexName string `cfg:"index_name"`
	// SPA is automatically redirect to index.html
	SPA bool `cfg:"spa"`
	// SPAEnableFile is enable .* file to be served to index.html if not found, default is false
	SPAEnableFile bool `cfg:"spa_enable_file"`
	// SPAIndex is set the index.html location, default is IndexName
	SPAIndex string `cfg:"spa_index"`
	// SPAIndexRegex sets SPAIndex from the first replacement that changes the URL path.
	// When no replacement changes it, SPAIndex is used.
	SPAIndexRegex []*RegexPathStore `cfg:"spa_index_regex"`
	// Browse is enable directory browsing
	Browse bool `cfg:"browse"`
	// UTC browse time format
	UTC bool `cfg:"utc"`
	// PrefixPath for strip prefix path for real file path
	PrefixPath string `cfg:"prefix_path"`
	// FilePathRegex is regex replacement for real file path, comes after PrefixPath apply
	// File path doesn't include / suffix
	//
	// The first replacement that changes the path wins; rewrites do not chain.
	FilePathRegex []*RegexPathStore `cfg:"file_path_regex"`

	// CacheRegex sets Cache-Control from the first rule matching the served
	// file's base name, not the request path.
	CacheRegex []*RegexCacheStore `cfg:"cache_regex"`
	// BrowseCache is cache control for browse page, default is no-cache
	BrowseCache string `cfg:"browse_cache"`

	DisableFolderSlashRedirect bool `cfg:"disable_folder_slash_redirect"`

	// ETag enables ETag generation for served files; empty disables it.
	//   - ETagWeak: W/"<modtime>-<size>", cheap and computed without reading
	//     the file. Files without a modtime (embed.FS) and responses with
	//     SetCustomContent get no ETag.
	//   - ETagStrong: "<sha256 of content>". Use it for embedded filesystems,
	//     where modtime is zero and Last-Modified is never sent. Hashes are
	//     cached per file path and refreshed when modtime or size changes;
	//     custom content is hashed on every request.
	// An ETag already set by an earlier handler is kept.
	ETag string `cfg:"etag"`
}

type RegexPathStore struct {
	Regex       string `cfg:"regex"`
	Replacement string `cfg:"replacement"`
	rgx         *regexp.Regexp
}

type RegexCacheStore struct {
	Regex        string `cfg:"regex"`
	CacheControl string `cfg:"cache_control"`
	rgx          *regexp.Regexp
}

type Folder struct {
	cfg *Config

	fs            http.FileSystem
	customContent func(r *http.Request, name string, content io.ReadSeeker) io.ReadSeeker
	etagCache     sync.Map // file path -> etagCacheEntry
}

func New(cfg *Config) (*Folder, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	snapshot := *cfg
	snapshot.SPAIndexRegex = cloneRegexPathStores(cfg.SPAIndexRegex)
	snapshot.FilePathRegex = cloneRegexPathStores(cfg.FilePathRegex)
	snapshot.CacheRegex = cloneRegexCacheStores(cfg.CacheRegex)
	cfg = &snapshot

	if cfg.IndexName == "" {
		cfg.IndexName = indexPage
	}

	cfg.IndexName = strings.Trim(cfg.IndexName, "/")

	if cfg.SPAIndex == "" {
		cfg.SPAIndex = cfg.IndexName
	}

	for i := range cfg.SPAIndexRegex {
		if cfg.SPAIndexRegex[i] == nil {
			return nil, fmt.Errorf("spa index regex at index %d is nil", i)
		}
		rgx, err := regexp.Compile(cfg.SPAIndexRegex[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile spa index regex %q: %w", cfg.SPAIndexRegex[i].Regex, err)
		}

		cfg.SPAIndexRegex[i].rgx = rgx
	}

	for i := range cfg.FilePathRegex {
		if cfg.FilePathRegex[i] == nil {
			return nil, fmt.Errorf("file path regex at index %d is nil", i)
		}
		rgx, err := regexp.Compile(cfg.FilePathRegex[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile file path regex %q: %w", cfg.FilePathRegex[i].Regex, err)
		}

		cfg.FilePathRegex[i].rgx = rgx
	}

	for i := range cfg.CacheRegex {
		if cfg.CacheRegex[i] == nil {
			return nil, fmt.Errorf("cache regex at index %d is nil", i)
		}
		rgx, err := regexp.Compile(cfg.CacheRegex[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile cache regex %q: %w", cfg.CacheRegex[i].Regex, err)
		}

		cfg.CacheRegex[i].rgx = rgx
	}

	switch cfg.ETag {
	case "", ETagWeak, ETagStrong:
	default:
		return nil, fmt.Errorf("unsupported etag mode %q, use %q or %q", cfg.ETag, ETagWeak, ETagStrong)
	}

	if cfg.BrowseCache == "" {
		cfg.BrowseCache = "no-cache"
	}

	if cfg.BasePath != "" {
		cfg.BasePath = "/" + strings.Trim(cfg.BasePath, "/") + "/"
	} else {
		cfg.BasePath = "/"
	}
	if cfg.PrefixPath != "" {
		cfg.PrefixPath = path.Clean("/" + strings.TrimPrefix(cfg.PrefixPath, "/"))
	}

	return &Folder{
		cfg: cfg,
		fs:  http.Dir(cfg.Path),
	}, nil
}

func cloneRegexPathStores(stores []*RegexPathStore) []*RegexPathStore {
	cloned := make([]*RegexPathStore, len(stores))
	for i, store := range stores {
		if store != nil {
			copy := *store
			copy.rgx = nil
			cloned[i] = &copy
		}
	}

	return cloned
}

func cloneRegexCacheStores(stores []*RegexCacheStore) []*RegexCacheStore {
	cloned := make([]*RegexCacheStore, len(stores))
	for i, store := range stores {
		if store != nil {
			copy := *store
			copy.rgx = nil
			cloned[i] = &copy
		}
	}

	return cloned
}

func (f *Folder) SetCustomContent(customContent func(r *http.Request, name string, content io.ReadSeeker) io.ReadSeeker) {
	f.customContent = customContent
}

func (f *Folder) SetFs(fs http.FileSystem) {
	f.fs = fs
}

func (f *Folder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
	}

	cPath := path.Clean(upath)
	if f.cfg.PrefixPath != "" {
		prefix := f.cfg.PrefixPath
		if prefix != "/" {
			if cPath != prefix && !strings.HasPrefix(cPath, prefix+"/") {
				handleError(w, newResponseError(http.StatusNotFound, nil))

				return
			}

			cPath = strings.TrimPrefix(cPath, prefix)
			if cPath == "" {
				cPath = "/"
			}
		}
	}

	for _, r := range f.cfg.FilePathRegex {
		cPathOrg := cPath
		cPath = r.rgx.ReplaceAllString(cPath, r.Replacement)
		if cPath != cPathOrg {
			break
		}
	}

	if err := f.serveFile(w, r, upath, cPath); err != nil {
		handleError(w, err)
	}
}

// name is '/'-separated, not filepath.Separator.
func (f *Folder) serveFile(w http.ResponseWriter, r *http.Request, uPath, cPath string) error {
	// redirect .../index.html to .../
	// can't use Redirect() because that would make the path absolute,
	// which would be a problem running under StripPrefix
	if f.cfg.StripIndexName && strings.HasSuffix(uPath, f.cfg.IndexName) {
		return localRedirect(w, r, strings.TrimSuffix(uPath, f.cfg.IndexName))
	}

	file, err := f.fs.Open(cPath)
	if err != nil {
		if os.IsNotExist(err) && f.cfg.SPA {
			if f.cfg.SPAEnableFile || !strings.Contains(path.Base(cPath), ".") {
				for _, spaR := range f.cfg.SPAIndexRegex {
					spaFile := spaR.rgx.ReplaceAllString(uPath, spaR.Replacement)
					if spaFile != uPath {
						return f.fsFile(w, r, spaFile)
					}
				}

				return f.fsFile(w, r, f.cfg.SPAIndex)
			}
		}

		return toHTTPError(err)
	}
	defer func(file http.File) { _ = file.Close() }(file)

	d, err := file.Stat()
	if err != nil {
		return toHTTPError(err)
	}

	// redirect to canonical path: / at end of directory url
	// r.URL.Path always begins with /
	if d.IsDir() {
		if uPath[len(uPath)-1] != '/' {
			if !f.cfg.DisableFolderSlashRedirect {
				return localRedirect(w, r, path.Base(uPath)+"/")
			}
		}
	} else {
		if uPath[len(uPath)-1] == '/' {
			return localRedirect(w, r, "../"+path.Base(uPath))
		}
	}

	filePath := cPath
	if d.IsDir() && f.cfg.Index {
		// use contents of index.html for directory, if present
		indexPath := path.Join(cPath, f.cfg.IndexName)
		ff, err := f.fs.Open(indexPath)
		if err == nil {
			defer func() { _ = ff.Close() }()
			dd, err := ff.Stat()
			if err == nil {
				d = dd
				file = ff
				filePath = indexPath
			}
		}
	}

	// Still a directory? (we didn't find an index.html file)
	if d.IsDir() {
		if f.cfg.Browse && BrowserFunc != nil {
			return BrowserFunc(w, r, BrowserOption{
				Folder:      file,
				UTC:         f.cfg.UTC,
				BasePath:    f.cfg.BasePath,
				BrowseCache: f.cfg.BrowseCache,
			})
		}

		return toHTTPError(os.ErrNotExist)
	}

	return f.fsFileInfo(w, r, filePath, d, file)
}

// localRedirect gives a Moved Permanently response.
// It does not convert relative paths to absolute paths like Redirect does.
func localRedirect(w http.ResponseWriter, r *http.Request, newPath string) error {
	if q := r.URL.RawQuery; q != "" {
		newPath += "?" + q
	}

	slog.Debug("redirecting to " + newPath)

	w.Header().Set("Location", newPath)
	w.WriteHeader(http.StatusMovedPermanently)

	return nil
}

// toHTTPError returns a non-specific HTTP error message for the given error.
func toHTTPError(err error) error {
	if os.IsNotExist(err) {
		return newResponseError(http.StatusNotFound, nil)
	}
	if os.IsPermission(err) {
		return newResponseError(http.StatusForbidden, nil)
	}

	return newResponseError(http.StatusInternalServerError, nil)
}

func (f *Folder) fsFile(w http.ResponseWriter, r *http.Request, file string) error {
	hFile, err := f.fs.Open(file)
	if err != nil {
		return toHTTPError(err)
	}
	defer func() { _ = hFile.Close() }()

	fi, err := hFile.Stat()
	if err != nil {
		return toHTTPError(err)
	}

	f.serveContent(w, r, file, fi.Name(), fi.ModTime(), hFile)

	return nil
}

func (f *Folder) fsFileInfo(w http.ResponseWriter, r *http.Request, filePath string, fi fs.FileInfo, file http.File) error {
	f.serveContent(w, r, filePath, fi.Name(), fi.ModTime(), file)

	return nil
}

func (f *Folder) cache(w http.ResponseWriter, fileName string) {
	for _, r := range f.cfg.CacheRegex {
		if r.rgx.MatchString(fileName) {
			w.Header().Set("Cache-Control", r.CacheControl)

			break
		}
	}
}

// serveContent serves the content; filePath is the key used to cache strong
// ETags.
func (f *Folder) serveContent(w http.ResponseWriter, req *http.Request, filePath, name string, modtime time.Time, content io.ReadSeeker) {
	f.cache(w, name)
	if f.customContent != nil {
		content = f.customContent(req, name, content)
	}

	if f.cfg.ETag != "" && w.Header().Get("ETag") == "" {
		etag, err := f.etag(filePath, modtime, content)
		if err != nil {
			slog.Warn("folder: cannot generate etag", "file", filePath, "error", err)
		} else if etag != "" {
			w.Header().Set("ETag", etag)
		}
	}

	http.ServeContent(w, req, name, modtime, content)
}
