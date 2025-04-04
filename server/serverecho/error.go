package serverecho

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/rakunlabs/rest"
)

func HTTPErrorHandler(err error, c echo.Context) {
	if he, ok := err.(*echo.HTTPError); ok {
		if he.Internal != nil {
			c.Logger().Error(he.Internal)
		}

		if he.Code == http.StatusInternalServerError {
			c.Logger().Error(err)
		}

		c.JSON(he.Code, rest.ResponseMessage{
			Message: &rest.Message{
				Text: "error.internal",
				Err:  err.Error(),
			},
		})
		return
	}

	c.Logger().Error(err)

	c.JSON(http.StatusInternalServerError, rest.ResponseMessage{
		Message: &rest.Message{
			Text:   "error.internal",
			Err:    err.Error(),
			Params: nil,
		},
	})
}
