package ada

import (
	"encoding/json"
	"net/http"
)

type HandlerFunc func(c *Context) error

var DefaultErrHandler = func(err error, c *Context) {
	c.SetStatus(http.StatusInternalServerError).SendJSON(map[string]string{"message": err.Error()})
}

// Wrap converts ada.HandlerFunc to http.HandlerFunc.
func (m *Mux) Wrap(handler HandlerFunc) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		c := NewContext(w, r)

		if err := handler(c); err != nil {
			if m.errHandler == nil {
				if DefaultErrHandler != nil {
					DefaultErrHandler(err, c)
				}
			} else {
				m.errHandler(err, c)
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

// SendNoContent always sends a 204 No Content response without body.
func (c *Context) SendNoContent() error {
	c.Response.WriteHeader(http.StatusNoContent)

	return nil
}
