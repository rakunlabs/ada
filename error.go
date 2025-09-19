package ada

import (
	"net/http"
)

var DefaultErrHandler = func(c *Context, err error) {
	statusCode := c.code
	if statusCode == 0 {
		statusCode = http.StatusInternalServerError
	}

	c.SetStatus(statusCode).SendJSON(map[string]string{"message": err.Error()})
}
