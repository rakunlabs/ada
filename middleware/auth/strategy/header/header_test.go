package header_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/middleware/auth/strategy/header"
)

func request(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/auth/login/pass/proxy", nil)
	r.RemoteAddr = remote

	for k, v := range headers {
		r.Header.Set(k, v)
	}

	return r
}

func TestLoginMapsHeaders(t *testing.T) {
	s := header.New("proxy", header.WithTrustedProxies("10.0.0.0/8"))

	rec := httptest.NewRecorder()
	r := request("10.1.2.3:5000", map[string]string{
		"X-Forwarded-User":   "alice",
		"X-Forwarded-Email":  "alice@example.com",
		"X-Forwarded-Name":   "Alice",
		"X-Forwarded-Roles":  "admin, staff",
		"X-Forwarded-Groups": "eng,ops",
	})

	id, outcome, err := s.Login(rec, r)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if outcome != strategy.OutcomeContinue {
		t.Fatalf("outcome = %v (%s)", outcome, rec.Body)
	}

	if id.Subject != "alice" || id.Email != "alice@example.com" || id.Name != "Alice" {
		t.Fatalf("identity = %+v", id)
	}

	if len(id.Roles) != 2 || id.Roles[0] != "admin" || id.Roles[1] != "staff" {
		t.Fatalf("roles = %v", id.Roles)
	}

	groups, _ := id.Claims["groups"].([]string)
	if len(groups) != 2 {
		t.Fatalf("groups = %v", id.Claims["groups"])
	}
}

// The gap this closes: without a trust boundary, anyone who can reach the
// endpoint is whoever they say they are.
func TestUntrustedPeerIsRejected(t *testing.T) {
	s := header.New("proxy", header.WithTrustedProxies("10.0.0.0/8"))

	rec := httptest.NewRecorder()
	r := request("203.0.113.9:5000", map[string]string{"X-Forwarded-User": "admin"})

	_, outcome, _ := s.Login(rec, r)

	if outcome != strategy.OutcomeFailed {
		t.Fatal("a peer outside the trusted CIDRs must not be able to claim an identity")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d", rec.Code)
	}
}

func TestForwardedForCannotForgeThePeer(t *testing.T) {
	s := header.New("proxy", header.WithTrustedProxies("10.0.0.0/8"))

	rec := httptest.NewRecorder()
	r := request("203.0.113.9:5000", map[string]string{
		"X-Forwarded-User": "admin",
		"X-Forwarded-For":  "10.1.2.3",
	})

	if _, outcome, _ := s.Login(rec, r); outcome != strategy.OutcomeFailed {
		t.Fatal("X-Forwarded-For must not be able to place a caller inside the trust boundary")
	}
}

func TestSharedSecret(t *testing.T) {
	s := header.New("proxy", header.WithSharedSecret("X-Proxy-Secret", "s3cret"))

	rec := httptest.NewRecorder()
	ok := request("203.0.113.9:5000", map[string]string{
		"X-Forwarded-User": "alice",
		"X-Proxy-Secret":   "s3cret",
	})

	if _, outcome, _ := s.Login(rec, ok); outcome != strategy.OutcomeContinue {
		t.Fatalf("correct secret rejected: %s", rec.Body)
	}

	rec = httptest.NewRecorder()
	bad := request("203.0.113.9:5000", map[string]string{
		"X-Forwarded-User": "alice",
		"X-Proxy-Secret":   "wrong",
	})

	if _, outcome, _ := s.Login(rec, bad); outcome != strategy.OutcomeFailed {
		t.Fatal("wrong secret accepted")
	}

	rec = httptest.NewRecorder()
	missing := request("203.0.113.9:5000", map[string]string{"X-Forwarded-User": "alice"})

	if _, outcome, _ := s.Login(rec, missing); outcome != strategy.OutcomeFailed {
		t.Fatal("missing secret accepted")
	}
}

// The rejection must be indistinguishable from a missing user header, so a
// probe cannot learn that a shared secret exists.
func TestRejectionIsIndistinguishable(t *testing.T) {
	s := header.New("proxy", header.WithSharedSecret("X-Proxy-Secret", "s3cret"))

	untrusted := httptest.NewRecorder()
	s.Login(untrusted, request("1.2.3.4:1", map[string]string{"X-Forwarded-User": "alice"})) //nolint:errcheck

	noUser := httptest.NewRecorder()
	s.Login(noUser, request("1.2.3.4:1", map[string]string{"X-Proxy-Secret": "s3cret"})) //nolint:errcheck

	if untrusted.Body.String() != noUser.Body.String() || untrusted.Code != noUser.Code {
		t.Errorf("responses differ:\n%d %s\n%d %s",
			untrusted.Code, untrusted.Body, noUser.Code, noUser.Body)
	}
}

func TestMissingUserHeader(t *testing.T) {
	s := header.New("proxy", header.WithTrustedProxies("10.0.0.0/8"))

	rec := httptest.NewRecorder()

	if _, outcome, _ := s.Login(rec, request("10.0.0.1:1", nil)); outcome != strategy.OutcomeFailed {
		t.Fatal("expected failure")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d", rec.Code)
	}
}

func TestNotARequestAuthenticator(t *testing.T) {
	s := header.New("proxy")

	// Deliberate: header identity is accepted at the login endpoint only, so a
	// misrouted deployment exposes one route rather than all of them.
	if _, ok := any(s).(strategy.RequestAuthenticator); ok {
		t.Fatal("header strategy must not authenticate arbitrary protected requests")
	}
}

func TestBareIPInTrustedProxies(t *testing.T) {
	s := header.New("proxy", header.WithTrustedProxies("192.168.1.5"))

	rec := httptest.NewRecorder()
	r := request("192.168.1.5:9000", map[string]string{"X-Forwarded-User": "alice"})

	if _, outcome, _ := s.Login(rec, r); outcome != strategy.OutcomeContinue {
		t.Fatalf("bare IP should be accepted as a /32: %s", rec.Body)
	}
}
