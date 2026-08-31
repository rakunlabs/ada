package passkey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	authstrategy "github.com/rakunlabs/ada/middleware/auth/strategy"
)

func counterTestFixture(t *testing.T) (*Config, *WebAuthn, *fakeAuthenticator, *Credential, User) {
	t.Helper()
	cfg := newTestConfig()
	webauthn, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := newFakeAuthenticator(t)
	user := User{Handle: []byte("counter-user"), Name: "counter-user"}
	credential := registerHelper(t, webauthn, authenticator, user, cfg.RPID, "http://localhost")
	credential.UserHandle = cloneBytes(user.Handle)
	return cfg, webauthn, authenticator, credential, user
}

func counterLookup(credential *Credential) CredentialLookup {
	return func(_ context.Context, credentialID []byte) (*Credential, *identity.Identity, error) {
		if !constantTimeBytesEqual(credentialID, credential.ID) {
			return nil, nil, ErrCredentialNotFound
		}
		cloned := *credential
		cloned.ID = cloneBytes(credential.ID)
		cloned.UserHandle = cloneBytes(credential.UserHandle)
		cloned.PublicKey = cloneBytes(credential.PublicKey)
		return &cloned, &identity.Identity{Subject: "counter-user"}, nil
	}
}

func counterFinishRequest(t *testing.T, strategy *Strategy, authenticator *fakeAuthenticator, cfg *Config, user User, sessionID string, count uint32) []byte {
	t.Helper()
	_, session, err := strategy.w.BeginLogin([][]byte{authenticator.credID})
	if err != nil {
		t.Fatal(err)
	}
	if err := strategy.store.Save(context.Background(), sessionID, session); err != nil {
		t.Fatal(err)
	}

	authenticator.signCount = count
	clientData := clientDataJSON(t, clientDataTypeGet, encodeBase64URL(session.Challenge), "http://localhost")
	authData := authenticator.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
	hash := sha256.Sum256(clientData)
	signature := signWith(t, authenticator.priv, append(authData, hash[:]...))
	assertionJSON := assertionBody(t, authenticator.credID, clientData, authData, signature, user.Handle)
	var assertion AssertionResponseJSON
	if err := json.Unmarshal(assertionJSON, &assertion); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(finishRequest{SessionID: sessionID, Assertion: assertion})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func executeCounterFinish(strategy *Strategy, body []byte) (*identity.Identity, authstrategy.Outcome, int) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	result, outcome, _ := strategy.Login(recorder, request)
	return result, outcome, recorder.Code
}

func TestStrategyCounterPersistenceFailureDeniesAuthentication(t *testing.T) {
	tests := []struct {
		name   string
		option Option
	}{
		{
			name: "legacy updater error",
			option: WithSignCountUpdater(func(context.Context, []byte, uint32) error {
				return errors.New("write failed")
			}),
		},
		{
			name: "atomic updater error",
			option: WithSignCountCompareAndAdvance(func(context.Context, []byte, uint32, uint32) (bool, error) {
				return false, errors.New("transaction failed")
			}),
		},
		{
			name: "atomic stale counter",
			option: WithSignCountCompareAndAdvance(func(context.Context, []byte, uint32, uint32) (bool, error) {
				return false, nil
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, webauthn, authenticator, credential, user := counterTestFixture(t)
			strategy, err := NewStrategy("passkey", webauthn, counterLookup(credential), test.option)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = strategy.Close() })

			body := counterFinishRequest(t, strategy, authenticator, cfg, user, "session", 1)
			result, outcome, status := executeCounterFinish(strategy, body)
			if result != nil || outcome != authstrategy.OutcomeFailed || status != http.StatusUnauthorized {
				t.Fatalf("Login() = (%v, %v, %d), want authentication failure", result, outcome, status)
			}
		})
	}
}

func TestStrategyWithoutUpdaterAllowsOnlyZeroCounters(t *testing.T) {
	cfg, webauthn, authenticator, credential, user := counterTestFixture(t)
	strategy, err := NewStrategy("passkey", webauthn, counterLookup(credential))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = strategy.Close() })

	nonzero := counterFinishRequest(t, strategy, authenticator, cfg, user, "nonzero", 1)
	if result, outcome, _ := executeCounterFinish(strategy, nonzero); result != nil || outcome != authstrategy.OutcomeFailed {
		t.Fatalf("nonzero counter without updater authenticated: result=%v outcome=%v", result, outcome)
	}

	zero := counterFinishRequest(t, strategy, authenticator, cfg, user, "zero", 0)
	if result, outcome, status := executeCounterFinish(strategy, zero); result == nil || outcome != authstrategy.OutcomeContinue || status != http.StatusOK {
		t.Fatalf("zero counter Login() = (%v, %v, %d), want success", result, outcome, status)
	}
}

func TestAtomicSignCountUpdateAcrossStrategiesAcceptsOnlyOneEqualCounter(t *testing.T) {
	cfg, webauthn, authenticator, credential, user := counterTestFixture(t)

	var storeMu sync.Mutex
	stored := *credential
	lookupReady := make(chan struct{}, 2)
	releaseLookup := make(chan struct{})
	lookup := func(_ context.Context, credentialID []byte) (*Credential, *identity.Identity, error) {
		storeMu.Lock()
		if !constantTimeBytesEqual(credentialID, stored.ID) {
			storeMu.Unlock()
			return nil, nil, ErrCredentialNotFound
		}
		snapshot := stored
		snapshot.ID = cloneBytes(stored.ID)
		snapshot.UserHandle = cloneBytes(stored.UserHandle)
		snapshot.PublicKey = cloneBytes(stored.PublicKey)
		storeMu.Unlock()
		lookupReady <- struct{}{}
		<-releaseLookup
		return &snapshot, &identity.Identity{Subject: "counter-user"}, nil
	}
	compareAndAdvance := func(_ context.Context, credentialID []byte, expected, next uint32) (bool, error) {
		storeMu.Lock()
		defer storeMu.Unlock()
		if !constantTimeBytesEqual(credentialID, stored.ID) {
			return false, ErrCredentialNotFound
		}
		if stored.SignCount != expected || next <= expected {
			return false, nil
		}
		stored.SignCount = next
		return true, nil
	}

	strategies := make([]*Strategy, 2)
	bodies := make([][]byte, 2)
	for i := range strategies {
		strategy, err := NewStrategy(
			fmt.Sprintf("passkey-%d", i),
			webauthn,
			lookup,
			WithSignCountCompareAndAdvance(compareAndAdvance),
		)
		if err != nil {
			t.Fatal(err)
		}
		strategies[i] = strategy
		t.Cleanup(func() { _ = strategy.Close() })
		bodies[i] = counterFinishRequest(t, strategy, authenticator, cfg, user, fmt.Sprintf("session-%d", i), 1)
	}

	results := make(chan bool, 2)
	for i := range strategies {
		go func() {
			result, outcome, _ := executeCounterFinish(strategies[i], bodies[i])
			results <- result != nil && outcome == authstrategy.OutcomeContinue
		}()
	}
	<-lookupReady
	<-lookupReady
	close(releaseLookup)

	succeeded := 0
	for range strategies {
		if <-results {
			succeeded++
		}
	}
	storeMu.Lock()
	finalCount := stored.SignCount
	storeMu.Unlock()
	if succeeded != 1 || finalCount != 1 {
		t.Fatalf("successful assertions = %d, stored count = %d; want 1 and 1", succeeded, finalCount)
	}
}

func TestStrategyRejectsConflictingCounterUpdaters(t *testing.T) {
	_, webauthn, _, credential, _ := counterTestFixture(t)
	_, err := NewStrategy(
		"passkey",
		webauthn,
		counterLookup(credential),
		WithSignCountUpdater(func(context.Context, []byte, uint32) error { return nil }),
		WithSignCountCompareAndAdvance(func(context.Context, []byte, uint32, uint32) (bool, error) { return true, nil }),
	)
	if err == nil {
		t.Fatal("NewStrategy accepted conflicting counter updaters")
	}
}
