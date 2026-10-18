package folder

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"time"
)

// etagCacheEntry is keyed by file path, so a changed file replaces its old
// entry instead of growing the cache.
type etagCacheEntry struct {
	modtime int64
	size    int64
	etag    string
}

// etag returns the ETag of content and rewinds it to the beginning. An empty
// result means no ETag can be produced.
func (f *Folder) etag(filePath string, modtime time.Time, content io.ReadSeeker) (string, error) {
	size, err := content.Seek(0, io.SeekEnd)
	if err != nil {
		return "", err
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	if f.cfg.ETag == ETagWeak {
		// Without modtime the size alone cannot identify the content, and
		// custom content may change per request while modtime stays the same.
		if modtime.IsZero() || f.customContent != nil {
			return "", nil
		}

		return `W/"` + strconv.FormatInt(modtime.UnixNano(), 36) + "-" + strconv.FormatInt(size, 36) + `"`, nil
	}

	// Custom content may differ per request, so it is never cached.
	cacheable := f.customContent == nil && filePath != ""
	if cacheable {
		if v, ok := f.etagCache.Load(filePath); ok {
			entry := v.(etagCacheEntry)
			if entry.modtime == modtime.UnixNano() && entry.size == size {
				return entry.etag, nil
			}
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, content); err != nil {
		return "", fmt.Errorf("hash content: %w", err)
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	etag := `"` + base64.RawURLEncoding.EncodeToString(h.Sum(nil)) + `"`
	if cacheable {
		f.etagCache.Store(filePath, etagCacheEntry{modtime: modtime.UnixNano(), size: size, etag: etag})
	}

	return etag, nil
}
