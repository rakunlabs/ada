package folder

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func newETagHandler(t *testing.T, cfg *Config) *Folder {
	t.Helper()

	handler, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return handler
}

func get(h http.Handler, path, ifNoneMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

func TestETag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{ETagWeak, ETagStrong} {
		t.Run(mode, func(t *testing.T) {
			h := newETagHandler(t, &Config{Path: dir, ETag: mode})

			rec := get(h, "/a.txt", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}

			etag := rec.Header().Get("ETag")
			if etag == "" {
				t.Fatal("etag is empty")
			}
			if weak := strings.HasPrefix(etag, "W/"); weak != (mode == ETagWeak) {
				t.Fatalf("unexpected etag %q for mode %s", etag, mode)
			}

			if rec := get(h, "/a.txt", etag); rec.Code != http.StatusNotModified {
				t.Fatalf("status = %d, want 304", rec.Code)
			}

			if rec := get(h, "/a.txt", `"other"`); rec.Code != http.StatusOK || rec.Body.String() != "hello" {
				t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestETagDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := get(newETagHandler(t, &Config{Path: dir}), "/a.txt", "").Header().Get("ETag"); got != "" {
		t.Fatalf("ETag = %q, want empty", got)
	}
}

func TestETagEmbedded(t *testing.T) {
	fsys := http.FS(fstest.MapFS{
		"a.txt":      {Data: []byte("hello")},
		"index.html": {Data: []byte("<h1>spa</h1>")},
	})

	t.Run("strong works without modtime", func(t *testing.T) {
		h := newETagHandler(t, &Config{ETag: ETagStrong})
		h.SetFs(fsys)

		etag := get(h, "/a.txt", "").Header().Get("ETag")
		if etag == "" {
			t.Fatal("strong etag must work without modtime")
		}
		if rec := get(h, "/a.txt", etag); rec.Code != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", rec.Code)
		}
	})

	t.Run("weak needs modtime", func(t *testing.T) {
		h := newETagHandler(t, &Config{ETag: ETagWeak})
		h.SetFs(fsys)

		rec := get(h, "/a.txt", "")
		if rec.Code != http.StatusOK || rec.Body.String() != "hello" {
			t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("ETag"); got != "" {
			t.Fatalf("ETag = %q, want empty", got)
		}
	})

	t.Run("spa fallback and index", func(t *testing.T) {
		h := newETagHandler(t, &Config{ETag: ETagStrong, SPA: true, Index: true})
		h.SetFs(fsys)

		spa := get(h, "/some/route", "").Header().Get("ETag")
		index := get(h, "/", "").Header().Get("ETag")
		if spa == "" || spa != index {
			t.Fatalf("spa etag = %q, index etag = %q", spa, index)
		}
		if rec := get(h, "/other/route", spa); rec.Code != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", rec.Code)
		}
	})
}

func TestETagChangesWithContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	h := newETagHandler(t, &Config{Path: dir, ETag: ETagStrong})

	first := get(h, "/a.txt", "").Header().Get("ETag")
	if again := get(h, "/a.txt", "").Header().Get("ETag"); again != first {
		t.Fatalf("cached etag = %q, want %q", again, first)
	}

	if err := os.WriteFile(p, []byte("world!"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(p, later, later); err != nil {
		t.Fatal(err)
	}

	if second := get(h, "/a.txt", "").Header().Get("ETag"); second == first {
		t.Fatalf("etag did not change: %s", first)
	}

	entries := 0
	h.etagCache.Range(func(_, _ any) bool {
		entries++
		return true
	})
	if entries != 1 {
		t.Fatalf("etag cache has %d entries, want 1", entries)
	}
}

func TestETagCustomContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{ETagWeak, ETagStrong} {
		t.Run(mode, func(t *testing.T) {
			h := newETagHandler(t, &Config{Path: dir, ETag: mode})
			h.SetCustomContent(func(r *http.Request, _ string, _ io.ReadSeeker) io.ReadSeeker {
				return strings.NewReader("user=" + r.URL.Query().Get("u"))
			})

			a := get(h, "/a.txt?u=a", "").Header().Get("ETag")
			b := get(h, "/a.txt?u=b", "").Header().Get("ETag")

			switch mode {
			case ETagWeak:
				if a != "" || b != "" {
					t.Fatalf("weak etag must be skipped for custom content: %q, %q", a, b)
				}
			case ETagStrong:
				if a == "" || a == b {
					t.Fatalf("strong etag must follow custom content: %q, %q", a, b)
				}
			}
		})
	}
}

func TestETagKeepsExistingHeader(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	h := newETagHandler(t, &Config{Path: dir, ETag: ETagStrong})
	rec := httptest.NewRecorder()
	rec.Header().Set("ETag", `"upstream"`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a.txt", nil))

	if got := rec.Header().Get("ETag"); got != `"upstream"` {
		t.Fatalf("ETag = %q", got)
	}
}

func TestETagInvalidMode(t *testing.T) {
	if _, err := New(&Config{ETag: "nope"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestIndexUsesSlashSeparatedPath(t *testing.T) {
	h := newETagHandler(t, &Config{Index: true})
	h.SetFs(http.FS(fstest.MapFS{"docs/index.html": {Data: []byte("docs index")}}))

	if rec := get(h, "/docs/", ""); rec.Code != http.StatusOK || rec.Body.String() != "docs index" {
		t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
	}
}
