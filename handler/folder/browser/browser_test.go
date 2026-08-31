package browser

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/handler/folder"
)

func TestBrowserEscapesNamesAndPathSegments(t *testing.T) {
	dir := t.TempDir()
	entries := []struct {
		name  string
		isDir bool
	}{
		{name: `"><img src=x onerror=alert(1)>&quot;.txt`},
		{name: `report #1?100%&done.txt`},
		{name: `archive #1?`, isDir: true},
	}
	for _, entry := range entries {
		if entry.isDir {
			if err := os.Mkdir(filepath.Join(dir, entry.name), 0o700); err != nil {
				t.Fatalf("create directory %q: %v", entry.name, err)
			}

			continue
		}
		if err := os.WriteFile(filepath.Join(dir, entry.name), []byte("test"), 0o600); err != nil {
			t.Fatalf("write %q: %v", entry.name, err)
		}
	}

	f, err := http.Dir(dir).Open("/")
	if err != nil {
		t.Fatalf("open directory: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close directory: %v", err)
		}
	}()

	rec := httptest.NewRecorder()
	err = Browser(rec, httptest.NewRequest(http.MethodGet, "/browse/", nil), folder.BrowserOption{
		BasePath: "/browse/",
		Folder:   f,
	})
	if err != nil {
		t.Fatalf("Browser: %v", err)
	}

	body := rec.Body.String()
	if strings.Contains(body, "<img src=x") {
		t.Fatalf("response contains executable filename markup: %s", body)
	}
	if !strings.Contains(body, "&lt;img") {
		t.Fatalf("response does not contain escaped filename markup: %s", body)
	}
	for _, entry := range entries {
		href := "./" + url.PathEscape(entry.name)
		if entry.isDir {
			href += "/"
		}
		href = html.EscapeString(href)
		if !strings.Contains(body, href) {
			t.Errorf("response does not contain escaped href %q", href)
		}
	}
}
