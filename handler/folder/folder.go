package folder

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const indexPage = "/index.html"

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
	// SPAIndexRegex set spa_index from URL path regex
	SPAIndexRegex []*RegexPathStore `cfg:"spa_index_regex"`
	// Browse is enable directory browsing
	Browse bool `cfg:"browse"`
	// UTC browse time format
	UTC bool `cfg:"utc"`
	// PrefixPath for strip prefix path for real file path
	PrefixPath string `cfg:"prefix_path"`
	// FilePathRegex is regex replacement for real file path, comes after PrefixPath apply
	// File path doesn't include / suffix
	FilePathRegex []*RegexPathStore `cfg:"file_path_regex"`

	CacheRegex []*RegexCacheStore `cfg:"cache_regex"`
	// BrowseCache is cache control for browse page, default is no-cache
	BrowseCache string `cfg:"browse_cache"`

	DisableFolderSlashRedirect bool `cfg:"disable_folder_slash_redirect"`
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
}

func New(cfg *Config) (*Folder, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	if cfg.IndexName == "" {
		cfg.IndexName = indexPage
	}

	cfg.IndexName = strings.Trim(cfg.IndexName, "/")

	if cfg.SPAIndex == "" {
		cfg.SPAIndex = cfg.IndexName
	}

	for i := range cfg.SPAIndexRegex {
		rgx, err := regexp.Compile(cfg.SPAIndexRegex[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile spa index regex %q: %w", cfg.SPAIndexRegex[i].Regex, err)
		}

		cfg.SPAIndexRegex[i].rgx = rgx
	}

	for i := range cfg.FilePathRegex {
		rgx, err := regexp.Compile(cfg.FilePathRegex[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile file path regex %q: %w", cfg.FilePathRegex[i].Regex, err)
		}

		cfg.FilePathRegex[i].rgx = rgx
	}

	for i := range cfg.CacheRegex {
		rgx, err := regexp.Compile(cfg.CacheRegex[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile cache regex %q: %w", cfg.CacheRegex[i].Regex, err)
		}

		cfg.CacheRegex[i].rgx = rgx
	}

	if cfg.BrowseCache == "" {
		cfg.BrowseCache = "no-cache"
	}

	if cfg.BasePath != "" {
		cfg.BasePath = "/" + strings.Trim(cfg.BasePath, "/") + "/"
	} else {
		cfg.BasePath = "/"
	}

	return &Folder{
		cfg: cfg,
		fs:  http.Dir(cfg.Path),
	}, nil
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
		prefix := strings.TrimSuffix(f.cfg.PrefixPath, "/")
		cPath = strings.TrimPrefix(cPath, prefix)
		if cPath == "" {
			cPath = "/"
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
			if f.cfg.SPAEnableFile || !strings.Contains(filepath.Base(cPath), ".") {
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
	defer file.Close()

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

	if d.IsDir() && f.cfg.Index {
		// use contents of index.html for directory, if present
		ff, err := f.fs.Open(filepath.Join(cPath, f.cfg.IndexName))
		if err == nil {
			defer ff.Close()
			dd, err := ff.Stat()
			if err == nil {
				d = dd
				file = ff
			}
		}
	}

	// Still a directory? (we didn't find an index.html file)
	if d.IsDir() {
		if f.cfg.Browse {
			return BrowserFunc(w, r, BrowserOption{
				Folder:      file,
				UTC:         f.cfg.UTC,
				BasePath:    f.cfg.BasePath,
				BrowseCache: f.cfg.BrowseCache,
			})
		}

		return toHTTPError(os.ErrNotExist)
	}

	return f.fsFileInfo(w, r, d, file)
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

	return err
}

func (f *Folder) fsFile(w http.ResponseWriter, r *http.Request, file string) error {
	hFile, err := f.fs.Open(file)
	if err != nil {
		return newResponseError(http.StatusNotFound, err)
	}
	defer hFile.Close()

	fi, err := hFile.Stat()
	if err != nil {
		return err
	}

	f.serveContent(w, r, fi.Name(), fi.ModTime(), hFile)

	return nil
}

func (f *Folder) fsFileInfo(w http.ResponseWriter, r *http.Request, fi fs.FileInfo, file http.File) error {
	f.serveContent(w, r, fi.Name(), fi.ModTime(), file)

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

func (f *Folder) serveContent(w http.ResponseWriter, req *http.Request, name string, modtime time.Time, content io.ReadSeeker) {
	f.cache(w, name)
	if f.customContent != nil {
		content = f.customContent(req, name, content)
	}

	http.ServeContent(w, req, name, modtime, content)
}
