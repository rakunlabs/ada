package oauth2

import (
	"net/http"
	"net/url"
)

// AuthHeaderStyle is a type to set Authorization header style.
type AuthHeaderStyle int

const (
	AuthHeaderStyleBasic AuthHeaderStyle = iota
	AuthHeaderStyleBearerSecret
	AuthHeaderStyleParams
)

// authHeader sets the Authorization header based on the style.
func authHeader(req *http.Request, clientID, clientSecret string, style AuthHeaderStyle) {
	if req == nil {
		return
	}

	switch style {
	case AuthHeaderStyleBasic:
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	case AuthHeaderStyleBearerSecret:
		req.Header.Add("Authorization", "Bearer "+clientSecret)
	}
}

// authParams sets client credentials as URL query parameters.
func authParams(clientID, clientSecret string, req *http.Request, style AuthHeaderStyle) {
	if style != AuthHeaderStyleParams || req == nil {
		return
	}

	query := req.URL.Query()
	if clientID != "" {
		query.Add("client_id", clientID)
	}
	if clientSecret != "" {
		query.Add("client_secret", clientSecret)
	}

	req.URL.RawQuery = query.Encode()
}
