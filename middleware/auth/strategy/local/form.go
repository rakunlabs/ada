package local

import "net/url"

// parseForm parses an x-www-form-urlencoded body into a flat string map. Used
// only when r.ParseForm fails to consume an already-buffered body (e.g. when
// the body has been read into memory upstream).
func parseForm(body string) (map[string]string, error) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return nil, err
	}

	out := make(map[string]string, len(values))
	for k, v := range values {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}

	return out, nil
}
