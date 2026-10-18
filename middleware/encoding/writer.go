package encoding

import (
	"net/http"
	"strconv"
	"strings"
)

// responseWriter buffers up to minLength bytes to decide whether the response
// is worth compressing. A Flush commits immediately so streaming responses are
// never delayed by the buffer.
type responseWriter struct {
	http.ResponseWriter

	encoding  string
	pool      *encoderPool
	minLength int
	filter    *contentTypeFilter

	status    int
	buf       []byte
	committed bool
	encoder   encoder
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if w.committed || w.status != 0 {
		return
	}

	if statusCode >= 100 && statusCode < 200 && statusCode != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(statusCode)

		return
	}

	w.status = statusCode

	if !w.compressible() {
		_ = w.commit(false)

		return
	}

	if cl := w.Header().Get("Content-Length"); cl != "" {
		if n, err := strconv.Atoi(cl); err == nil && n < w.minLength {
			_ = w.commit(false)
		}
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}

	if w.committed {
		if w.encoder != nil {
			return w.encoder.Write(b)
		}

		return w.ResponseWriter.Write(b)
	}

	w.buf = append(w.buf, b...)
	if len(w.buf) < w.minLength {
		return len(b), nil
	}

	if err := w.commit(true); err != nil {
		return 0, err
	}

	return len(b), nil
}

// compressible checks the status and headers. When Content-Type is not set
// yet, it is sniffed from the buffered body at commit time.
func (w *responseWriter) compressible() bool {
	switch {
	case w.status < 200,
		w.status == http.StatusNoContent,
		w.status == http.StatusNotModified,
		w.status == http.StatusPartialContent:
		return false
	}

	h := w.Header()
	if h.Get("Content-Encoding") != "" || h.Get("Content-Range") != "" {
		return false
	}

	for directive := range strings.SplitSeq(h.Get("Cache-Control"), ",") {
		if strings.EqualFold(strings.TrimSpace(directive), "no-transform") {
			return false
		}
	}

	if ct := h.Get("Content-Type"); ct != "" && !w.filter.allowed(ct) {
		return false
	}

	return true
}

// commit writes the header and the buffered data. compress is the caller's
// wish; the headers are checked again before compressing.
func (w *responseWriter) commit(compress bool) error {
	if w.committed {
		return nil
	}

	w.committed = true

	h := w.Header()
	if h.Get("Content-Type") == "" && len(w.buf) > 0 {
		h.Set("Content-Type", http.DetectContentType(w.buf))
	}

	if compress && w.compressible() {
		h.Set("Content-Encoding", w.encoding)
		h.Del("Content-Length")
		weakenETag(h)

		w.encoder = w.pool.get(w.ResponseWriter)
	}

	if w.status == 0 {
		w.status = http.StatusOK
	}

	w.ResponseWriter.WriteHeader(w.status)

	if len(w.buf) == 0 {
		return nil
	}

	buf := w.buf
	w.buf = nil

	var err error
	if w.encoder != nil {
		_, err = w.encoder.Write(buf)
	} else {
		_, err = w.ResponseWriter.Write(buf)
	}

	return err
}

// weakenETag marks a strong ETag as weak because the encoded body differs
// byte-by-byte from the original representation.
func weakenETag(h http.Header) {
	etag := h.Get("ETag")
	if etag != "" && !strings.HasPrefix(etag, "W/") {
		h.Set("ETag", "W/"+etag)
	}
}

func (w *responseWriter) Flush() {
	_ = w.FlushError()
}

func (w *responseWriter) FlushError() error {
	if !w.committed {
		// A flush marks a streaming response; compress it even if it is small so far.
		if err := w.commit(true); err != nil {
			return err
		}
	}

	if w.encoder != nil {
		if err := w.encoder.Flush(); err != nil {
			return err
		}
	}

	return http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController discover capabilities of the original writer.
func (w *responseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *responseWriter) close() {
	if !w.committed {
		if w.status == 0 && len(w.buf) == 0 {
			// The handler wrote nothing.
			return
		}

		// The body is smaller than MinLength.
		_ = w.commit(false)
	}

	if w.encoder != nil {
		_ = w.encoder.Close()
		w.pool.put(w.encoder)
		w.encoder = nil
	}
}
