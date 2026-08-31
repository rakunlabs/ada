package folder

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestPrefixPathRequiresSegmentMatchAfterCleaning(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"public.txt": "public",
		"secret.txt": "secret",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	handler, err := New(&Config{Path: dir, PrefixPath: "/files/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tests := []struct {
		path string
		code int
		body string
	}{
		{path: "/files/public.txt", code: http.StatusOK, body: "public"},
		{path: "/secret.txt", code: http.StatusNotFound},
		{path: "/filessecret.txt", code: http.StatusNotFound},
		{path: "/files/../secret.txt", code: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != tt.code {
				t.Fatalf("status = %d, want %d; body = %q", rec.Code, tt.code, rec.Body.String())
			}
			if tt.body != "" && rec.Body.String() != tt.body {
				t.Fatalf("body = %q, want %q", rec.Body.String(), tt.body)
			}
		})
	}
}

type failingFileSystem struct {
	err error
}

func (f failingFileSystem) Open(string) (http.File, error) {
	return nil, f.err
}

func TestInternalFileSystemErrorsAreNotExposed(t *testing.T) {
	const sensitive = "storage failure at /srv/private/customer-data"
	handler, err := New(&Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler.SetFs(failingFileSystem{err: errors.New(sensitive)})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/file.txt", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if strings.Contains(rec.Body.String(), sensitive) {
		t.Fatalf("response exposed internal error: %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), http.StatusText(http.StatusInternalServerError)) {
		t.Fatalf("body = %q, want generic internal server error", rec.Body.String())
	}
}

func TestNewSnapshotsConfigAndRegexRules(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"public.txt": "public",
		"secret.txt": "secret",
		"spa.html":   "spa",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	fileRule := &RegexPathStore{Regex: `^/alias$`, Replacement: "/public.txt"}
	spaRule := &RegexPathStore{Regex: `^/assets/app/.*$`, Replacement: "/spa.html"}
	cacheRule := &RegexCacheStore{Regex: `\.txt$`, CacheControl: "public, max-age=60"}
	cfg := &Config{
		BasePath:      "browse",
		Path:          dir,
		PrefixPath:    "assets/",
		SPA:           true,
		SPAIndexRegex: []*RegexPathStore{spaRule},
		FilePathRegex: []*RegexPathStore{fileRule},
		CacheRegex:    []*RegexCacheStore{cacheRule},
	}
	handler, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if cfg.IndexName != "" || cfg.BasePath != "browse" || cfg.PrefixPath != "assets/" {
		t.Fatalf("New mutated caller config: %#v", cfg)
	}
	if fileRule.rgx != nil || spaRule.rgx != nil || cacheRule.rgx != nil {
		t.Fatal("New compiled regular expressions into caller-owned rules")
	}

	// Mutate both the caller's slice storage and the pointed-to rules. The
	// constructed handler must retain the original behavior.
	cfg.PrefixPath = "/changed"
	cfg.SPA = false
	cfg.FilePathRegex[0] = &RegexPathStore{Regex: `.*`, Replacement: "/secret.txt"}
	cfg.SPAIndexRegex[0] = &RegexPathStore{Regex: `.*`, Replacement: "/secret.txt"}
	cfg.CacheRegex[0] = &RegexCacheStore{Regex: `.*`, CacheControl: "no-store"}
	fileRule.Replacement = "/secret.txt"
	spaRule.Replacement = "/secret.txt"
	cacheRule.CacheControl = "no-store"

	assertSnapshot := func(path, wantBody string, wantCache bool) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != wantBody {
			t.Errorf("%s: status = %d, body = %q; want 200, %q", path, rec.Code, rec.Body.String(), wantBody)
		}
		if wantCache && rec.Header().Get("Cache-Control") != "public, max-age=60" {
			t.Errorf("%s: Cache-Control = %q, want snapshot value", path, rec.Header().Get("Cache-Control"))
		}
	}
	assertSnapshot("/assets/alias", "public", true)
	assertSnapshot("/assets/app/dashboard", "spa", false)

	const (
		workers    = 8
		iterations = 100
	)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers + 1)
	go func() {
		defer wg.Done()
		<-start
		for i := range workers * iterations {
			cfg.PrefixPath = "/changed/" + string(rune('a'+i%26))
			cfg.SPA = i%2 == 0
			fileRule.Replacement = []string{"/secret.txt", "/missing.txt"}[i%2]
			spaRule.Replacement = []string{"/secret.txt", "/missing.txt"}[i%2]
			cacheRule.CacheControl = []string{"no-store", "private"}[i%2]
			cfg.FilePathRegex[0] = &RegexPathStore{Regex: `.*`, Replacement: "/secret.txt"}
			cfg.SPAIndexRegex[0] = &RegexPathStore{Regex: `.*`, Replacement: "/secret.txt"}
			cfg.CacheRegex[0] = &RegexCacheStore{Regex: `.*`, CacheControl: "no-store"}
			if i%16 == 0 {
				runtime.Gosched()
			}
		}
	}()
	for worker := range workers {
		go func(worker int) {
			defer wg.Done()
			<-start
			for i := range iterations {
				if (worker+i)%2 == 0 {
					assertSnapshot("/assets/alias", "public", true)
				} else {
					assertSnapshot("/assets/app/dashboard", "spa", false)
				}
			}
		}(worker)
	}
	close(start)
	wg.Wait()
}
