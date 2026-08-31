package passkey

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

func TestNewSnapshotsCallerConfig(t *testing.T) {
	origins := []string{"https://example.com"}
	algorithms := []CredentialAlgorithm{{COSE: algES256, Name: "ES256"}}
	cfg := &Config{
		RPID:             "example.com",
		RPDisplayName:    "Example",
		RPOrigins:        origins,
		UserVerification: UVRequired,
		ChallengeTTL:     time.Minute,
		Algorithms:       algorithms,
	}
	wa, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	origins[0] = "https://evil.example"
	algorithms[0] = CredentialAlgorithm{COSE: algEdDSA, Name: "EdDSA"}
	cfg.RPID = "evil.example"
	cfg.UserVerification = UVDiscouraged
	cfg.ChallengeTTL = time.Hour

	options, session, err := wa.BeginRegistration(User{Handle: []byte("user"), Name: "user"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if options.RP.ID != "example.com" || options.AuthenticatorSelection.UserVerification != string(UVRequired) {
		t.Fatalf("construction policy changed after caller mutation: %+v", options)
	}
	if len(options.PubKeyCredParams) != 1 || options.PubKeyCredParams[0].Alg != algES256 {
		t.Fatalf("algorithm offer changed after caller mutation: %+v", options.PubKeyCredParams)
	}
	if session.UserVerification != UVRequired || time.Until(session.Expires) > 2*time.Minute {
		t.Fatalf("session policy changed after caller mutation: %+v", session)
	}
}

func TestNewDoesNotApplyDefaultsToCaller(t *testing.T) {
	cfg := newTestConfig()
	wa, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserVerification != "" || cfg.ChallengeTTL != 0 || cfg.Algorithms != nil {
		t.Fatalf("New mutated caller config: %+v", cfg)
	}
	if wa.cfg.UserVerification != UVPreferred || wa.cfg.ChallengeTTL != 5*time.Minute || len(wa.cfg.Algorithms) == 0 {
		t.Fatalf("defaults not applied to owned config: %+v", wa.cfg)
	}
}

func TestNewRejectsInvalidPolicyValues(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
	}{
		{
			name: "user verification",
			configure: func(cfg *Config) {
				cfg.UserVerification = UserVerification("require")
			},
		},
		{
			name: "unsupported algorithm",
			configure: func(cfg *Config) {
				cfg.Algorithms = []CredentialAlgorithm{{COSE: -999, Name: "unknown"}}
			},
		},
		{
			name: "duplicate algorithm",
			configure: func(cfg *Config) {
				cfg.Algorithms = []CredentialAlgorithm{{COSE: algES256}, {COSE: algES256}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := newTestConfig()
			test.configure(cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("New unexpectedly accepted invalid policy")
			}
		})
	}
}

func TestBeginRegistrationRejectsInvalidAttachment(t *testing.T) {
	wa, err := New(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = wa.BeginRegistration(
		User{Handle: []byte("user"), Name: "user"},
		nil,
		WithAuthenticatorAttachment("crossplatform"),
	)
	if err == nil || !strings.Contains(err.Error(), "authenticator attachment") {
		t.Fatalf("BeginRegistration error = %v, want invalid attachment", err)
	}
}

func TestBeginClonesCallerPolicySlices(t *testing.T) {
	wa, err := New(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}

	handle := []byte("user")
	excluded := []PublicKeyCredentialDescriptor{{
		Type:       "public-key",
		ID:         "credential",
		Transports: []string{"internal"},
	}}
	options, registration, err := wa.BeginRegistration(User{Handle: handle, Name: "user"}, excluded)
	if err != nil {
		t.Fatal(err)
	}
	handle[0] = 'X'
	excluded[0].Transports[0] = "usb"
	if string(registration.UserHandle) != "user" {
		t.Fatalf("registration user handle aliases caller bytes: %q", registration.UserHandle)
	}
	if options.ExcludeCredentials[0].Transports[0] != "internal" {
		t.Fatalf("excluded transports alias caller slice: %+v", options.ExcludeCredentials)
	}

	allowed := [][]byte{{1, 2, 3}}
	_, login, err := wa.BeginLogin(allowed)
	if err != nil {
		t.Fatal(err)
	}
	allowed[0][0] = 9
	allowed[0] = []byte{8}
	if got := login.AllowedCredentialIDs[0]; len(got) != 3 || got[0] != 1 {
		t.Fatalf("login allow list aliases caller bytes: %v", got)
	}
}

func TestWebAuthnCallerConfigMutationIsRaceFree(t *testing.T) {
	cfg := &Config{
		RPID:      "localhost",
		RPOrigins: []string{"http://localhost"},
		Algorithms: []CredentialAlgorithm{
			{COSE: algES256, Name: "ES256"},
		},
	}
	wa, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cfg.RPID = "mutated.invalid"
			cfg.RPOrigins[0] = "http://mutated.invalid"
			cfg.Algorithms[0].COSE = algEdDSA
		}
	}()
	for i := 0; i < 100; i++ {
		if _, _, err := wa.BeginRegistration(User{Handle: []byte("user"), Name: "user"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestNewStrategySnapshotsWebAuthn(t *testing.T) {
	wa, err := New(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := NewStrategy("passkey", wa, func(context.Context, []byte) (*Credential, *identity.Identity, error) {
		return nil, nil, ErrCredentialNotFound
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = strategy.Close() })

	wa.cfg.RPOrigins[0] = "https://evil.example"
	wa.cfg.Algorithms[0].COSE = algEdDSA
	if strategy.w.cfg.RPOrigins[0] != "http://localhost" || strategy.w.cfg.Algorithms[0].COSE != algES256 {
		t.Fatal("strategy retained the caller-owned WebAuthn configuration")
	}
}

func TestFinishRejectsInvalidSessionPolicy(t *testing.T) {
	wa, err := New(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := wa.BeginLogin(nil)
	if err != nil {
		t.Fatal(err)
	}
	session.UserVerification = UserVerification("require")
	if _, err := wa.FinishLogin(session, nil, nil); err == nil || !strings.Contains(err.Error(), "invalid session UserVerification") {
		t.Fatalf("FinishLogin error = %v, want invalid session policy", err)
	}
}
