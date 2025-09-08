package ada

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rakunlabs/ada/utils/bind"
)

type HandlerFunc func(c *Context) error

// Wrap converts ada.HandlerFunc to http.HandlerFunc.
func (m *Mux) Wrap(handler HandlerFunc) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		c := NewContext(w, r)

		if err := handler(c); err != nil {
			if m.errHandler == nil {
				if DefaultErrHandler != nil {
					DefaultErrHandler(c, err)
				}
			} else {
				m.errHandler(c, err)
			}
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
func (c *Context) SetHeader(key, value string) *Context {
	c.Response.Header().Set(key, value)

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

	return &HandlerError{
		Code: c.code,
		Err:  err,
	}
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

func (c *Context) SendJSONRaw(data []byte) error {
	c.Response.Header().Set(HeaderContentType, MIMEApplicationJSONCharsetUTF8)
	c.Response.WriteHeader(c.code)

	_, err := c.Response.Write(data)

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

// SendIO streams data from an io.Reader to the response.
//   - Content-Type should be set via SetHeader before calling this method.
func (c *Context) SendIO(reader io.Reader) error {
	c.Response.WriteHeader(c.code)

	_, err := io.Copy(c.Response, reader)

	return err
}
