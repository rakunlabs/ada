package oauth2

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestAuthBody_PostStyleAddsBodyParams verifies client_secret_post places the
// credentials in the request body form parameters.
func TestAuthBody_PostStyleAddsBodyParams(t *testing.T) {
	values := url.Values{"grant_type": {"authorization_code"}}

	authBody("cid", "secret", values, AuthHeaderStylePost)

	if got := values.Get("client_id"); got != "cid" {
		t.Errorf("client_id in body: got %q, want %q", got, "cid")
	}
	if got := values.Get("client_secret"); got != "secret" {
		t.Errorf("client_secret in body: got %q, want %q", got, "secret")
	}
}

// TestAuthBody_NonPostStylesLeaveBodyUntouched verifies the body is not given
// credentials for any style other than Post (those use header/query instead).
func TestAuthBody_NonPostStylesLeaveBodyUntouched(t *testing.T) {
	for _, style := range []AuthHeaderStyle{
		AuthHeaderStyleBasic,
		AuthHeaderStyleBearerSecret,
		AuthHeaderStyleParams,
	} {
		values := url.Values{"grant_type": {"authorization_code"}}

		authBody("cid", "secret", values, style)

		if values.Has("client_id") || values.Has("client_secret") {
			t.Errorf("style %d: credentials must not be added to the body", style)
		}
	}
}

// TestAuthHeader_BasicSetsBasicAuth verifies the default style sets HTTP Basic.
func TestAuthHeader_BasicSetsBasicAuth(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://idp.example.com/token", strings.NewReader(""))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	authHeader(req, "cid", "secret", AuthHeaderStyleBasic)

	user, pass, ok := req.BasicAuth()
	if !ok || user != "cid" || pass != "secret" {
		t.Errorf("basic auth: got user=%q pass=%q ok=%v", user, pass, ok)
	}
}

// TestAuthHeader_PostStyleSetsNoAuthorizationHeader verifies client_secret_post
// does not also set an Authorization header (credentials live in the body).
func TestAuthHeader_PostStyleSetsNoAuthorizationHeader(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://idp.example.com/token", strings.NewReader(""))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	authHeader(req, "cid", "secret", AuthHeaderStylePost)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("post style must not set Authorization header, got %q", got)
	}
}

// TestAuthParams_PostStyleSetsNoQueryParams verifies client_secret_post does not
// leak the credentials into the URL query string.
func TestAuthParams_PostStyleSetsNoQueryParams(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://idp.example.com/token", strings.NewReader(""))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	authParams("cid", "secret", req, AuthHeaderStylePost)

	if req.URL.Query().Has("client_secret") {
		t.Errorf("post style must not add credentials to the query string")
	}
}

// TestParseAuthHeaderStyle covers the aliases, the legacy numeric forms, and
// the unknown case.
func TestParseAuthHeaderStyle(t *testing.T) {
	cases := []struct {
		in    string
		want  AuthHeaderStyle
		wantO bool
	}{
		{"", AuthHeaderStyleBasic, true},
		{"basic", AuthHeaderStyleBasic, true},
		{"  Client_Secret_Basic ", AuthHeaderStyleBasic, true},
		{"0", AuthHeaderStyleBasic, true},
		{"bearer", AuthHeaderStyleBearerSecret, true},
		{"1", AuthHeaderStyleBearerSecret, true},
		{"query", AuthHeaderStyleParams, true},
		{"params", AuthHeaderStyleParams, true},
		{"2", AuthHeaderStyleParams, true},
		{"post", AuthHeaderStylePost, true},
		{"body", AuthHeaderStylePost, true},
		{"client_secret_post", AuthHeaderStylePost, true},
		{"3", AuthHeaderStylePost, true},
		{"nonsense", AuthHeaderStyleBasic, false},
	}

	for _, c := range cases {
		got, ok := ParseAuthHeaderStyle(c.in)
		if got != c.want || ok != c.wantO {
			t.Errorf("ParseAuthHeaderStyle(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.wantO)
		}
	}
}

// TestAuthHeaderStyle_TextRoundTrip verifies String/MarshalText/UnmarshalText
// are consistent and that an unknown value is rejected.
func TestAuthHeaderStyle_TextRoundTrip(t *testing.T) {
	for _, style := range []AuthHeaderStyle{
		AuthHeaderStyleBasic,
		AuthHeaderStyleBearerSecret,
		AuthHeaderStyleParams,
		AuthHeaderStylePost,
	} {
		text, err := style.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", style, err)
		}

		var back AuthHeaderStyle
		if err := back.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}

		if back != style {
			t.Errorf("round-trip: got %v, want %v (text %q)", back, style, text)
		}
	}

	var s AuthHeaderStyle
	if err := s.UnmarshalText([]byte("nope")); err == nil {
		t.Errorf("UnmarshalText(\"nope\") should error")
	}
}
