package folder

import (
	"encoding/json"
	"errors"
	"net/http"
)

type response struct {
	Message string `json:"message"`
}

type codeError struct {
	Code int
	Err  error
}

func (e *codeError) Error() string {
	if e.Err == nil || e.Err.Error() == "" {
		return http.StatusText(e.Code)
	}

	return e.Err.Error()
}

func (e *codeError) Unwrap() error {
	return e.Err
}

func newResponseError(code int, err error) *codeError {
	return &codeError{
		Code: code,
		Err:  err,
	}
}

// ///////////////////////////////////////////

func handleError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	var resp *codeError
	if errors.As(err, &resp) {
		if resp.Code == 0 {
			resp.Code = http.StatusInternalServerError
		}

		w.WriteHeader(resp.Code)
		_ = json.NewEncoder(w).Encode(response{
			Message: resp.Error(),
		})
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(response{
			Message: http.StatusText(http.StatusInternalServerError),
		})
	}
}
