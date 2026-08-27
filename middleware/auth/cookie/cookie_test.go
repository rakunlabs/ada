package cookie_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/cookie"
)

func TestDefaultsAreTheSecureOnes(t *testing.T) {
	o := cookie.Options{}.WithDefaults()

	if o.Path != "/" {
		t.Errorf("path = %q, want /", o.Path)
	}

	if o.SameSite != http.SameSiteLaxMode {
		t.Errorf("same site = %v, want Lax", o.SameSite)
	}

	if o.Secure != cookie.SecureAuto {
		t.Errorf("secure = %q, want auto", o.Secure)
	}

	// The regression this guards: an unconfigured session cookie used to ship
	// with HttpOnly=false because the zero value of a bool is false.
	c := o.Build(httptest.NewRequest(http.MethodGet, "/", nil), "s", "v")
	if !c.HttpOnly {
		t.Error("HttpOnly must default to true")
	}
}

func TestSecureAuto(t *testing.T) {
	o := cookie.Options{}.WithDefaults()

	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	if o.Build(plain, "s", "v").Secure {
		t.Error("plaintext request should not get Secure")
	}

	tls := httptest.NewRequest(http.MethodGet, "/", nil)
	tls.Header.Set("X-Forwarded-Proto", "https")

	if !o.Build(tls, "s", "v").Secure {
		t.Error("forwarded https should get Secure")
	}

	chained := httptest.NewRequest(http.MethodGet, "/", nil)
	chained.Header.Set("X-Forwarded-Proto", "https, http")

	if !o.Build(chained, "s", "v").Secure {
		t.Error("first hop of a forwarded chain decides")
	}
}

func TestSecureModes(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "/", nil)

	always := cookie.Options{Secure: cookie.SecureAlways}.WithDefaults()
	if !always.Build(plain, "s", "v").Secure {
		t.Error("always should force Secure")
	}

	never := cookie.Options{Secure: cookie.SecureNever}.WithDefaults()

	tlsReq := httptest.NewRequest(http.MethodGet, "/", nil)
	tlsReq.Header.Set("X-Forwarded-Proto", "https")

	if never.Build(tlsReq, "s", "v").Secure {
		t.Error("never should suppress Secure")
	}
}

func TestSecureModeUnmarshalText(t *testing.T) {
	cases := map[string]cookie.SecureMode{
		"":       cookie.SecureAuto,
		"auto":   cookie.SecureAuto,
		"ALWAYS": cookie.SecureAlways,
		" never": cookie.SecureNever,
		"true":   cookie.SecureAlways,
		"false":  cookie.SecureNever,
	}

	for in, want := range cases {
		var got cookie.SecureMode
		if err := got.UnmarshalText([]byte(in)); err != nil {
			t.Fatalf("%q: %v", in, err)
		}

		if got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}

	var bad cookie.SecureMode
	if err := bad.UnmarshalText([]byte("maybe")); err == nil {
		t.Error("expected error for unknown mode")
	}
}

func TestValidateRejectsSameSiteNoneWithoutSecure(t *testing.T) {
	o := cookie.Options{SameSite: http.SameSiteNoneMode, Secure: cookie.SecureNever}.WithDefaults()
	if err := o.Validate(); err == nil {
		t.Error("SameSite=None without Secure is dropped by browsers; it should not validate")
	}
}

func TestDeleteMatchesBuildAttributes(t *testing.T) {
	o := cookie.Options{Domain: "example.com", Path: "/x"}.WithDefaults()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	set := o.Build(r, "s", "v")
	del := o.Delete(r, "s")

	if del.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", del.MaxAge)
	}

	// A tombstone with different attributes leaves the original in place.
	if del.Path != set.Path || del.Domain != set.Domain || del.Secure != set.Secure || del.SameSite != set.SameSite {
		t.Errorf("delete attributes diverge from set: %+v vs %+v", del, set)
	}
}

func TestDisableHTTPOnly(t *testing.T) {
	o := cookie.Options{DisableHTTPOnly: true}.WithDefaults()

	c := o.Build(httptest.NewRequest(http.MethodGet, "/", nil), "s", "v")
	if c.HttpOnly {
		t.Error("DisableHTTPOnly should clear HttpOnly")
	}
}
