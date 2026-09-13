package jwt

import (
	"encoding/json"
	"strings"
	"time"
)

// Claims is a decoded JWT payload with typed accessors.
//
// JSON gives every number back as a float64 and every list as []any, and
// several standard claims are "string or array of strings" by spec. Reading
// them by hand at each call site is how `aud` ends up checked in one place
// and ignored in another.
type Claims map[string]any

// String returns a string claim, or "" when absent or of another type.
func (c Claims) String(key string) string {
	s, _ := c[key].(string)

	return s
}

// Bool returns a boolean claim and whether it was present as a boolean.
func (c Claims) Bool(key string) (bool, bool) {
	b, ok := c[key].(bool)

	return b, ok
}

// Float returns a numeric claim and whether it was present as a number.
//
// json.Number is handled so callers that decode with UseNumber are not
// silently told every timestamp is missing.
func (c Claims) Float(key string) (float64, bool) {
	switch v := c[key].(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()

		return f, err == nil
	case int64:
		return float64(v), true
	case int:
		return float64(v), true
	}

	return 0, false
}

// Time returns a NumericDate claim (exp, nbf, iat, auth_time) as a time.
func (c Claims) Time(key string) (time.Time, bool) {
	seconds, ok := c.Float(key)
	if !ok {
		return time.Time{}, false
	}

	whole, frac := int64(seconds), seconds-float64(int64(seconds))

	return time.Unix(whole, int64(frac*float64(time.Second))), true
}

// Strings returns a claim that may be a single string or a list of strings.
// Non-string entries in a list are dropped rather than stringified, so a
// malformed `aud` cannot widen an audience check by accident.
func (c Claims) Strings(key string) []string {
	switch v := c[key].(type) {
	case string:
		if v == "" {
			return nil
		}

		return []string{v}
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}

		return out
	}

	return nil
}

// Audience returns the `aud` claim as a list.
func (c Claims) Audience() []string {
	return c.Strings("aud")
}

// Scopes returns the granted scopes.
//
// RFC 8693 §4.2 defines `scope` as a space-delimited string; several issuers
// (notably AWS Cognito and some Spring stacks) publish `scp` as an array
// instead. Both are read, because a resource server that understands only one
// of them rejects half the ecosystem.
func (c Claims) Scopes() []string {
	if raw := c.String("scope"); raw != "" {
		return strings.Fields(raw)
	}

	if scp := c.Strings("scp"); len(scp) > 0 {
		return scp
	}

	// `scope` as an array is not standard but appears in the wild.
	return c.Strings("scope")
}

// Lookup resolves a dotted path (e.g. "realm_access.roles") through nested
// objects and returns the value at the end of it.
//
// Roles live wherever the issuer decided to put them — `roles` for turna,
// `realm_access.roles` for Keycloak, `resource_access.<client>.roles` for a
// Keycloak client scope. A dotted path is the difference between supporting
// one issuer and supporting all of them.
func (c Claims) Lookup(path string) (any, bool) {
	if path == "" {
		return nil, false
	}

	var current any = map[string]any(c)

	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}

		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}

	return current, true
}

// StringsAt is Strings for a dotted path.
func (c Claims) StringsAt(path string) []string {
	if !strings.Contains(path, ".") {
		return c.Strings(path)
	}

	value, ok := c.Lookup(path)
	if !ok {
		return nil
	}

	return Claims{"v": value}.Strings("v")
}

// StringAt is String for a dotted path.
func (c Claims) StringAt(path string) string {
	if !strings.Contains(path, ".") {
		return c.String(path)
	}

	value, ok := c.Lookup(path)
	if !ok {
		return ""
	}

	s, _ := value.(string)

	return s
}

// ContainsAudience reports whether want appears in the `aud` claim.
func (c Claims) ContainsAudience(want string) bool {
	for _, aud := range c.Audience() {
		if aud == want {
			return true
		}
	}

	return false
}
