package forwardauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// IdentityExtractor is the batteries-included extractor: it JSON-decodes the
// auth response body into identity.Identity and stores it on the request
// context via identity.WithContext. Downstream handlers read it back with
// identity.FromContext.
//
// Contract with the auth service:
//   - 2xx body must be JSON matching the identity.Identity shape.
//   - Empty body is treated as a protocol violation and fails the request.
//   - Malformed JSON or body exceeding WithMaxBodySize fails the request.
//
// Fail-closed on any of the above: 502 Bad Gateway, WithOnError observes.
var IdentityExtractor ExtractorFunc = func(r *http.Request, resp *http.Response) (*http.Request, error) {
	var id identity.Identity

	dec := json.NewDecoder(resp.Body)

	if err := dec.Decode(&id); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("identity extractor: empty body")
		}

		return nil, fmt.Errorf("identity extractor: %w", err)
	}

	return r.WithContext(identity.WithContext(r.Context(), &id)), nil
}
