package oauth2

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Errors returned by ID token claim validation.
var (
	ErrIssuerMismatch   = errors.New("oauth2: id_token issuer mismatch")
	ErrAudienceMismatch = errors.New("oauth2: id_token audience mismatch")
	ErrTokenExpired     = errors.New("oauth2: id_token expired")
	ErrTokenNotYetValid = errors.New("oauth2: id_token not yet valid")
	ErrNonceMismatch    = errors.New("oauth2: id_token nonce mismatch")
)

// idTokenChecks is what validateIDToken enforces. Every field that is empty or
// zero is skipped, so a caller can relax an individual check deliberately
// instead of switching validation off wholesale.
type idTokenChecks struct {
	Issuer   string
	Audience string
	Nonce    string
	Skew     time.Duration
	Now      time.Time
}

// validateIDToken applies the OIDC Core §3.1.3.7 checks to already
// signature-verified claims.
//
// Signature verification alone proves the token was minted by the IdP. It says
// nothing about who the token was minted *for*: without the audience check, an
// ID token issued to any other client of the same IdP is accepted here, and
// without the nonce check a token captured from an earlier login can be
// replayed into a new one.
func validateIDToken(claims map[string]any, c idTokenChecks) error {
	now := c.Now
	if now.IsZero() {
		now = time.Now()
	}

	if c.Issuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != c.Issuer {
			return fmt.Errorf("%w: got %q, want %q", ErrIssuerMismatch, iss, c.Issuer)
		}
	}

	if c.Audience != "" && !audienceContains(claims["aud"], c.Audience) {
		return fmt.Errorf("%w: %q not in aud", ErrAudienceMismatch, c.Audience)
	}

	if exp, ok := numericDate(claims["exp"]); ok {
		if now.After(exp.Add(c.Skew)) {
			return fmt.Errorf("%w at %s", ErrTokenExpired, exp.UTC().Format(time.RFC3339))
		}
	} else if c.Issuer != "" {
		// "exp" is REQUIRED by the spec. A token without one never goes stale.
		return errors.New("oauth2: id_token has no exp claim")
	}

	if nbf, ok := numericDate(claims["nbf"]); ok {
		if now.Add(c.Skew).Before(nbf) {
			return ErrTokenNotYetValid
		}
	}

	if c.Nonce != "" {
		got, _ := claims["nonce"].(string)
		if subtle.ConstantTimeCompare([]byte(got), []byte(c.Nonce)) != 1 {
			return ErrNonceMismatch
		}
	}

	return nil
}

// audienceContains handles both shapes the aud claim is allowed to take: a
// single string or an array of them.
func audienceContains(raw any, want string) bool {
	switch v := raw.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}

	return false
}

// numericDate reads a JWT NumericDate. JSON decoding gives float64, but some
// IdPs send it as a string.
func numericDate(raw any) (time.Time, bool) {
	switch v := raw.(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case int64:
		return time.Unix(v, 0), true
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return time.Unix(n, 0), true
		}
	case string:
		var n int64
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return time.Unix(n, 0), true
		}
	}

	return time.Time{}, false
}
