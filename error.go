package ada

import (
	"encoding/json"
	"errors"
	"net/http"
)

var DefaultErrHandler = func(c *Context, err error) {
	var errResp *HandlerError
	if errors.As(err, &errResp) {
		c.SetStatus(errResp.Code).SendJSON(errResp)
		return
	}

	c.SetStatus(http.StatusInternalServerError).SendJSON(map[string]string{"message": err.Error()})
}

type HandlerError struct {
	Code int   `json:"-"`
	Err  error `json:"-"`
}

func (e HandlerError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Message string `json:"message"`
	}{
		Message: e.Err.Error(),
	})
}

func (e HandlerError) Error() string {
	return e.Err.Error()
}

func (e HandlerError) Unwrap() error {
	return e.Err
}
