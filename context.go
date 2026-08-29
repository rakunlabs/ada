package ada

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"

	"github.com/rakunlabs/ada/utils/bind"
)

type HandlerFunc func(c *Context) error

var escaper = strings.NewReplacer(`"`, `\"`, `\`, `\\`)

// Wrap converts HandlerFunc to http.HandlerFunc using the Mux error handler.
//   - The routing methods accept a HandlerFunc directly and bind it to the Mux
//     for you, so this is only needed to hand an ada handler to another router.
func (m *Mux) Wrap(handler HandlerFunc) http.HandlerFunc {
	return wrap(handler, m.handleContextError)
}

// WrapUnpooled converts HandlerFunc to http.HandlerFunc without recycling its
// Context after the handler returns. Prefer Wrap for normal request handling;
// use this compatibility path only when code must retain the Context itself
// after return. The Request and Response can be retained independently without
// opting out of pooling.
func (m *Mux) WrapUnpooled(handler HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := NewContext(w, r)
		if err := handler(c); err != nil {
			c.prepareError(err)
			m.handleContextError(c, err)
		}
	}
}

func (m *Mux) handleContextError(c *Context, err error) {
	if m.errHandler != nil {
		m.errHandler(c, err)

		return
	}

	defaultErrHandler(c, err)
}

func defaultErrHandler(c *Context, err error) {
	if DefaultErrHandler != nil {
		DefaultErrHandler(c, err)
	}
}

// contextPool recycles the per-request Context. A Context is three words plus
// two flags, but allocating one per request was the single largest source of
// garbage on the Context-handler path — it was one of only four allocations in
// a JSON response, and the only one ada controls.
//
// A Context recovered from the pool is fully reinitialised by acquireContext,
// so no state can leak between requests.
var contextPool = sync.Pool{
	New: func() any { return new(Context) },
}

// acquireContext returns a Context bound to this request, taken from the pool
// when one is available.
func acquireContext(w http.ResponseWriter, r *http.Request) *Context {
	c, _ := contextPool.Get().(*Context)

	c.Request = r
	c.Response = w
	c.code = http.StatusOK
	c.committed = false

	return c
}

// releaseContext clears the request references and returns the Context to the
// pool.
//
// The references must be dropped before the Put: a pooled Context that still
// points at a finished request keeps that request, its body and its
// ResponseWriter alive for as long as the Context sits in the pool.
func releaseContext(c *Context) {
	c.Request = nil
	c.Response = nil

	contextPool.Put(c)
}

func wrap(handler HandlerFunc, errHandler func(c *Context, err error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := acquireContext(w, r)

		if err := handler(c); err != nil {
			c.prepareError(err)
			errHandler(c, err)
		}

		// Deliberately not deferred, and deliberately skipped when the
		// handler panics: an escaping panic unwinds past this point and
		// the Context is simply left to the garbage collector rather
		// than recycled while a recover middleware may still be reading
		// it.
		releaseContext(c)
	}
}

// ////////////////////////////////////////////

// Context carries the request and response for one handler invocation.
//
// A Context handed to a HandlerFunc is pooled and recycled once that handler
// returns. It is valid for the duration of the call only: do not store it in a
// struct, capture it in a goroutine that outlives the handler, or otherwise use
// it after returning. Copy whatever you need out of it instead — c.Request and
// c.Response stay valid on their own.
//
// Contexts built with NewContext are not pooled and have no such restriction.
type Context struct {
	Request  *http.Request
	Response http.ResponseWriter

	code      int
	committed bool
}

// NewContext returns a standalone Context. It is not drawn from (nor returned
// to) the pool, so the result outlives the handler that made it.
func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	return &Context{
		Request:  r,
		Response: w,

		code: http.StatusOK,
	}
}

// commit claims the right to write the response, returning false if some
// earlier Send* already did.
//
// Without this, a handler that writes a response and then returns an error
// produced two concatenated bodies and a "superfluous WriteHeader" from
// net/http, with the status of whichever write happened to land first.
//
// Note this only tracks writes made through the Send* methods. A handler that
// writes to c.Response directly is invisible to it.
func (c *Context) commit() bool {
	if c.committed {
		return false
	}

	c.committed = true

	return true
}

// Committed reports whether the response has already been written through one
// of the Send* methods.
func (c *Context) Committed() bool {
	return c.committed
}

// prepareError normalises the status before the error handler runs, so an
// error can never be reported with a 2xx.
//   - An HTTPError anywhere in the chain supplies the status.
//   - Otherwise a status below 400 is promoted to 500; an explicit 4xx/5xx
//     already set with SetStatus is preserved.
func (c *Context) prepareError(err error) {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.Code != 0 {
		c.code = httpErr.Code

		return
	}

	if c.code < 400 {
		c.code = http.StatusInternalServerError
	}
}

// Bind binds the request data to the provided struct based on content type and struct tags.
//   - The obj parameter must be a pointer.
func (c *Context) Bind(obj any) error {
	return bind.Bind(c.Request, obj)
}

// SetHeader sets a response header.
//
//	SetHeader("Content-Type", "application/json", "X-Custom-Header", "value")
func (c *Context) SetHeader(kv ...string) *Context {
	for i := 0; i+1 < len(kv); i += 2 {
		key := kv[i]
		value := kv[i+1]
		c.Response.Header().Set(key, value)
	}

	return c
}

// SetStatus sets the response status code.
//   - Use http package constants for standard status codes like http.StatusOK
func (c *Context) SetStatus(code int) *Context {
	c.code = code

	return c
}

func (c *Context) Err(err error) error {
	if c.code < 400 {
		c.code = http.StatusInternalServerError
	}

	return err
}

// contentType sets the response Content-Type unless one is already set.
//
// A handler that picked its own type — `c.SetHeader("Content-Type",
// "application/problem+json").SendJSON(...)` is the usual case — used to have
// it silently replaced by the Send* method's default.
func (c *Context) contentType(value string) {
	header := c.Response.Header()
	if header.Get(HeaderContentType) == "" {
		header.Set(HeaderContentType, value)
	}
}

// //////////////////////////////////////////

// SendJSON sends a json response.
func (c *Context) SendJSON(data any) error {
	return c.SendJSONP(data, "")
}

// SendJSONP sends a json pretty-printed response.
func (c *Context) SendJSONP(data any, indent string) error {
	if !c.commit() {
		return ErrAlreadyCommitted
	}

	c.contentType(MIMEApplicationJSONCharsetUTF8)
	c.Response.WriteHeader(c.code)

	encoder := json.NewEncoder(c.Response)
	encoder.SetIndent("", indent)

	return encoder.Encode(data)
}

func (c *Context) SendJSONRaw(data io.Reader) error {
	if !c.commit() {
		return ErrAlreadyCommitted
	}

	c.contentType(MIMEApplicationJSONCharsetUTF8)
	c.Response.WriteHeader(c.code)

	_, err := io.Copy(c.Response, data)

	return err
}

// SendNoContent always sends a 204 No Content response without body.
func (c *Context) SendNoContent() error {
	if !c.commit() {
		return ErrAlreadyCommitted
	}

	c.Response.WriteHeader(http.StatusNoContent)

	return nil
}

func (c *Context) SendString(s string) error {
	if !c.commit() {
		return ErrAlreadyCommitted
	}

	c.contentType(MIMETextPlainCharsetUTF8)
	c.Response.WriteHeader(c.code)

	_, err := c.Response.Write([]byte(s))

	return err
}

// SendBlob streams data from an io.Reader to the response.
//   - The caller is responsible for setting appropriate headers (e.g., Content-Type).
func (c *Context) SendBlob(reader io.Reader) error {
	if !c.commit() {
		return ErrAlreadyCommitted
	}

	c.Response.WriteHeader(c.code)

	_, err := io.Copy(c.Response, reader)

	return err
}

// SendFile sends a single file to the client.
func (c *Context) SendFile(name string, reader io.Reader) error {
	if !c.commit() {
		return ErrAlreadyCommitted
	}

	c.contentType(MIMEOctetStream)
	c.Response.Header().Set(HeaderContentDisposition, `attachment; filename="`+escaper.Replace(name)+`"`)
	c.Response.WriteHeader(c.code)

	_, err := io.Copy(c.Response, reader)

	return err
}

// SendZip sends files to the client as a zip file.
//   - If name is empty, defaults to "files.zip".
func (c *Context) SendZip(name string, files map[string]io.Reader) error {
	if c.Committed() {
		return ErrAlreadyCommitted
	}

	if name == "" {
		name = "files.zip"
	}

	// Multiple files: create zip
	buf := &bytes.Buffer{}
	zipWriter := zip.NewWriter(buf)

	for filename, reader := range files {
		entryName, err := cleanZipEntryName(filename)
		if err != nil {
			_ = zipWriter.Close()

			return err
		}

		fileWriter, err := zipWriter.Create(entryName)
		if err != nil {
			zipWriter.Close()

			return fmt.Errorf("failed to create zip entry for %s: %w", filename, err)
		}
		_, err = io.Copy(fileWriter, reader)
		if err != nil {
			zipWriter.Close()

			return fmt.Errorf("failed to copy data for %s: %w", filename, err)
		}
	}

	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("failed to close zip writer: %w", err)
	}
	if !c.commit() {
		return ErrAlreadyCommitted
	}

	c.contentType(MIMEOctetStream)
	c.Response.Header().Set(HeaderContentDisposition, `attachment; filename="`+escaper.Replace(name)+`"`)
	c.Response.WriteHeader(c.code)

	_, err := io.Copy(c.Response, buf)

	return err
}

// cleanZipEntryName validates an archive member name independently from HTTP
// Content-Disposition escaping. ZIP names always use forward slashes and must
// be relative; accepting traversal, absolute or drive-qualified paths creates
// archives that unsafe extractors can write outside their destination.
func cleanZipEntryName(name string) (string, error) {
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("invalid zip entry name %q", name)
	}

	name = strings.ReplaceAll(name, `\`, "/")
	clean := path.Clean(name)

	if clean == "." || clean == ".." || path.IsAbs(clean) || strings.HasPrefix(clean, "../") ||
		(len(clean) >= 2 && clean[1] == ':') {
		return "", fmt.Errorf("unsafe zip entry name %q", name)
	}

	return clean, nil
}
