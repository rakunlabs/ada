package ada

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rakunlabs/ada/utils/bind"
)

type HandlerFunc func(c *Context) error

var escaper = strings.NewReplacer(`"`, `\"`, `\`, `\\`)

// Wrap converts HandlerFunc to http.HandlerFunc using the Mux error handler.
//   - The routing methods accept a HandlerFunc directly and bind it to the Mux
//     for you, so this is only needed to hand an ada handler to another router.
func (m *Mux) Wrap(handler HandlerFunc) http.HandlerFunc {
	return wrap(handler, func(c *Context, err error) {
		if m.errHandler != nil {
			m.errHandler(c, err)

			return
		}

		defaultErrHandler(c, err)
	})
}

func defaultErrHandler(c *Context, err error) {
	if DefaultErrHandler != nil {
		DefaultErrHandler(c, err)
	}
}

func wrap(handler HandlerFunc, errHandler func(c *Context, err error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := NewContext(w, r)

		if err := handler(c); err != nil {
			errHandler(c, err)
		}
	}
}

// ////////////////////////////////////////////

type Context struct {
	Request  *http.Request
	Response http.ResponseWriter

	code int
}

func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	return &Context{
		Request:  r,
		Response: w,

		code: http.StatusOK,
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

// //////////////////////////////////////////

// SendJSON sends a json response.
func (c *Context) SendJSON(data any) error {
	return c.SendJSONP(data, "")
}

// SendJSONP sends a json pretty-printed response.
func (c *Context) SendJSONP(data any, indent string) error {
	c.Response.Header().Set(HeaderContentType, MIMEApplicationJSONCharsetUTF8)
	c.Response.WriteHeader(c.code)

	encoder := json.NewEncoder(c.Response)
	encoder.SetIndent("", indent)

	return encoder.Encode(data)
}

func (c *Context) SendJSONRaw(data io.Reader) error {
	c.Response.Header().Set(HeaderContentType, MIMEApplicationJSONCharsetUTF8)
	c.Response.WriteHeader(c.code)

	_, err := io.Copy(c.Response, data)

	return err
}

// SendNoContent always sends a 204 No Content response without body.
func (c *Context) SendNoContent() error {
	c.Response.WriteHeader(http.StatusNoContent)

	return nil
}

func (c *Context) SendString(s string) error {
	c.Response.Header().Set(HeaderContentType, MIMETextPlainCharsetUTF8)
	c.Response.WriteHeader(c.code)

	_, err := c.Response.Write([]byte(s))

	return err
}

// SendBlob streams data from an io.Reader to the response.
//   - The caller is responsible for setting appropriate headers (e.g., Content-Type).
func (c *Context) SendBlob(reader io.Reader) error {
	c.Response.WriteHeader(c.code)

	_, err := io.Copy(c.Response, reader)

	return err
}

// SendFile sends a single file to the client.
func (c *Context) SendFile(name string, reader io.Reader) error {
	c.Response.Header().Set(HeaderContentType, MIMEOctetStream)
	c.Response.Header().Set(HeaderContentDisposition, `attachment; filename="`+escaper.Replace(name)+`"`)
	c.Response.WriteHeader(c.code)

	_, err := io.Copy(c.Response, reader)

	return err
}

// SendZip sends files to the client as a zip file.
//   - If name is empty, defaults to "files.zip".
func (c *Context) SendZip(name string, files map[string]io.Reader) error {
	if name == "" {
		name = "files.zip"
	}

	// Multiple files: create zip
	buf := &bytes.Buffer{}
	zipWriter := zip.NewWriter(buf)

	for filename, reader := range files {
		fileWriter, err := zipWriter.Create(escaper.Replace(filename))
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

	c.Response.Header().Set(HeaderContentType, MIMEOctetStream)
	c.Response.Header().Set(HeaderContentDisposition, `attachment; filename="`+escaper.Replace(name)+`"`)
	c.Response.WriteHeader(c.code)

	_, err := io.Copy(c.Response, buf)

	return err
}
