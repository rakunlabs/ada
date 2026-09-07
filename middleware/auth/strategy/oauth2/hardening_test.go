package oauth2

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

func startFlow(t *testing.T, s *Strategy) (*url.URL, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	_, outcome, err := s.Login(w, httptest.NewRequest("GET", "https://app.example/login", nil))
	if err != nil || outcome != strategy.OutcomePending {
		t.Fatalf("initiate: %v %v %s", outcome, err, w.Body)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u, w.Result().Cookies()[0]
}

func flowRequest(u *url.URL, c *http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", u.Query().Get("redirect_uri")+"?code=code&state="+u.Query().Get("state"), nil)
	r.AddCookie(c)
	return r
}

func genericStrategy(t *testing.T) (*Strategy, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/token" {
			_ = r.ParseForm()
			if r.Form.Get("code_verifier") == "" {
				t.Error("missing PKCE verifier")
			}
			_, _ = io.WriteString(w, `{"access_token":"access"}`)
		} else {
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Error("missing bearer")
			}
			_, _ = io.WriteString(w, `{"sub":"alice"}`)
		}
	}))
	t.Cleanup(srv.Close)
	return New("idp", Config{ClientID: "client", AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token", UserInfoURL: srv.URL + "/userinfo"}, Options{}), calls
}

func TestGenericFlowAtomicCallback(t *testing.T) {
	s, calls := genericStrategy(t)
	replica := New(s.name, s.cfg, s.opts)
	u, c := startFlow(t, s)
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 32 {
		t.Fatal("cookie is not an opaque 256-bit handle")
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := range 24 {
		worker := s
		if i%2 == 1 {
			worker = replica
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			id, outcome, err := worker.Login(w, flowRequest(u, c))
			if err != nil {
				t.Error(err)
			}
			if outcome == strategy.OutcomeContinue {
				if id == nil || id.Subject != "alice" {
					t.Errorf("identity=%+v", id)
				}
				successes.Add(1)
			} else if w.Code != 401 {
				t.Errorf("status=%d", w.Code)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Error("cacheable callback")
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || calls.Load() != 2 {
		t.Fatalf("successes=%d upstream calls=%d", successes.Load(), calls.Load())
	}
}

func TestFlowRejectsAndConsumesInvalidCallbacks(t *testing.T) {
	for _, name := range []string{"state", "missing state", "duplicate state", "duplicate code", "duplicate other query", "code and error", "empty code", "no query", "malformed query", "duplicate cookie", "malformed duplicate cookie", "two browser cookies", "legacy cookie", "wrong browser", "wrong provider", "wrong client", "wrong callback", "wrong path", "wrong host", "expired", "denied"} {
		t.Run(name, func(t *testing.T) {
			s, calls := genericStrategy(t)
			u, c := startFlow(t, s)
			r := flowRequest(u, c)
			switch name {
			case "state":
				r.URL.RawQuery = "code=x&state=wrong"
			case "missing state":
				r.URL.RawQuery = "code=x"
			case "duplicate state":
				r.URL.RawQuery += "&state=" + u.Query().Get("state")
			case "duplicate code":
				r.URL.RawQuery += "&code=code"
			case "duplicate other query":
				r.URL.RawQuery += "&extra=x&extra=x"
			case "code and error":
				r.URL.RawQuery += "&error=access_denied"
			case "empty code":
				r.URL.RawQuery = "code=&state=" + u.Query().Get("state")
			case "no query":
				r.URL.RawQuery = ""
			case "malformed query":
				r.URL.RawQuery += "&bad=%ZZ"
			case "duplicate cookie":
				r.AddCookie(c)
			case "malformed duplicate cookie":
				r.Header.Add("Cookie", c.Name+`="unterminated`)
			case "two browser cookies":
				u2, c2 := startFlow(t, s)
				r.AddCookie(c2)
				t.Cleanup(func() {
					w := httptest.NewRecorder()
					_, _, _ = s.Login(w, flowRequest(u2, c2))
					if w.Code != 401 {
						t.Error("second ambiguous cookie not consumed")
					}
				})
			case "legacy cookie":
				r.Header.Set("Cookie", c.Name+"="+base64.RawURLEncoding.EncodeToString([]byte(`{"s":"state","n":"nonce","v":"verifier"}`)))
			case "wrong browser":
				_, c2 := startFlow(t, s)
				r.Header.Del("Cookie")
				r.AddCookie(c2)
			case "wrong provider":
				s.name = "other"
				r.Header.Set("Cookie", s.flowCookieName()+"="+c.Value)
			case "wrong client":
				s.cfg.ClientID = "other"
			case "wrong callback":
				s.opts.CallbackBasePath = "/other"
			case "wrong path":
				r.URL.Path = "/other"
			case "wrong host":
				r.Host = "other.example"
			case "expired":
				m := s.flows.(*memoryFlowStore)
				f := m.flows[c.Value]
				f.ExpiresAt = time.Now()
				m.flows[c.Value] = f
			case "denied":
				r.URL.RawQuery = "error=access_denied&state=" + u.Query().Get("state")
			}
			w := httptest.NewRecorder()
			id, outcome, err := s.Login(w, r)
			if err != nil || id != nil || outcome != strategy.OutcomeFailed || w.Code != 401 {
				t.Fatalf("invalid callback: %v %v %v %d %s", id, outcome, err, w.Code, w.Body)
			}
			if calls.Load() != 0 {
				t.Fatal("invalid flow reached upstream")
			}
			if name == "legacy cookie" || name == "wrong browser" {
				return
			} // no possession of the original handle
			s.name = "idp"
			s.cfg.ClientID = "client"
			s.opts.CallbackBasePath = ""
			w = httptest.NewRecorder()
			_, _, _ = s.Login(w, flowRequest(u, c))
			if w.Code != 401 || calls.Load() != 0 {
				t.Fatal("invalid callback left reusable flow")
			}
		})
	}
}

type failingFlowStore struct {
	saveErr, consumeErr error
	flow                FlowData
}

func (f *failingFlowStore) Save(context.Context, string, FlowData) error { return f.saveErr }
func (f *failingFlowStore) Consume(context.Context, string) (FlowData, error) {
	return f.flow, f.consumeErr
}

func TestFlowStoreFailuresAndExpiry(t *testing.T) {
	s, calls := genericStrategy(t)
	for _, name := range []string{"save", "consume", "expired injected record"} {
		t.Run(name, func(t *testing.T) {
			store := &failingFlowStore{}
			s.flows = store
			w := httptest.NewRecorder()
			if name == "save" {
				store.saveErr = errors.New("storage unavailable SECRET")
				_, _, _ = s.Login(w, httptest.NewRequest("GET", "https://app.example/login", nil))
				if len(w.Result().Cookies()) != 0 {
					t.Fatal("issued cookie on failed save")
				}
			} else {
				u, c := startFlow(t, s)
				store.consumeErr = errors.New("storage unavailable SECRET")
				if name == "expired injected record" {
					store.consumeErr = nil
					store.flow = FlowData{State: u.Query().Get("state"), Provider: s.flowProvider(), CallbackURL: u.Query().Get("redirect_uri"), ExpiresAt: time.Now()}
				}
				_, _, _ = s.Login(w, flowRequest(u, c))
			}
			want := 503
			if name == "expired injected record" {
				want = 401
			}
			if w.Code != want || strings.Contains(w.Body.String(), "SECRET") || calls.Load() != 0 {
				t.Fatalf("response=%d %s calls=%d", w.Code, w.Body, calls.Load())
			}
		})
	}
}

func TestMemoryFlowStoreBoundsTTLAndCancellation(t *testing.T) {
	m := &memoryFlowStore{flows: make(map[string]FlowData)}
	ctx := context.Background()
	f := FlowData{ExpiresAt: time.Now().Add(time.Hour)}
	for i := range 4096 {
		f.Source = fmt.Sprint(i)
		if err := m.Save(ctx, fmt.Sprint(i), f); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Save(ctx, "overflow", f); !errors.Is(err, ErrFlowStoreFull) {
		t.Fatalf("capacity: %v", err)
	}
	if err := m.Save(ctx, "0", f); !errors.Is(err, ErrFlowInvalid) {
		t.Fatalf("overwrite: %v", err)
	}
	m.flows["0"] = FlowData{ExpiresAt: time.Now()}
	if err := m.Save(ctx, "new", f); err != nil {
		t.Fatalf("lazy prune: %v", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.Consume(ctx, "new"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := m.Save(ctx, "cancelled", f); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := m.Consume(context.Background(), "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Consume(context.Background(), "new"); !errors.Is(err, ErrFlowInvalid) {
		t.Fatal(err)
	}
}

func TestFlowLifetimeAndDefaultStoreReplacement(t *testing.T) {
	s, calls := genericStrategy(t)
	if s.opts.FlowTTL != 6*time.Minute {
		t.Fatalf("default TTL=%s", s.opts.FlowTTL)
	}
	s.opts.FlowTTL = time.Minute
	s.flowCookie.MaxAge = 3600 // Browser lifetime must not override server TTL.
	before := time.Now()
	u, c := startFlow(t, s)
	f := s.flows.(*memoryFlowStore).flows[c.Value]
	if f.ExpiresAt.Before(before.Add(time.Minute)) || f.ExpiresAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("server expiry=%s", f.ExpiresAt)
	}
	if f.Nonce == "" || f.Verifier == "" || f.State != u.Query().Get("state") {
		t.Fatal("missing server-held secrets")
	}
	replacement := New(s.name, s.cfg, Options{})
	w := httptest.NewRecorder()
	_, _, _ = replacement.Login(w, flowRequest(u, c))
	if w.Code != 401 || calls.Load() != 0 {
		t.Fatal("default replacement accepted old flow")
	}
	// Failure in an independent store cannot consume another store's record.
	w = httptest.NewRecorder()
	_, outcome, _ := s.Login(w, flowRequest(u, c))
	if outcome != strategy.OutcomeContinue {
		t.Fatalf("original flow=%d %s", w.Code, w.Body)
	}
}

func TestOAuthErrorCodeAllowlist(t *testing.T) {
	for _, body := range []string{`{"error":"SECRET_CODE","error_description":"SECRET_DESC"}`, `SECRET_HTML`, `{"error":{"SECRET":"VALUE"}}`} {
		err := responseError("token", 400, []byte(body))
		if strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "code=unknown") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
}

type secretTransport struct{}

func (secretTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("transport failed at %s SECRET_TRANSPORT", r.URL)
}

func TestOAuthLogsNeverIncludeUpstreamSecrets(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, operation := range []string{"token", "userinfo", "discovery", "logout", "revoke", "callback"} {
		for _, transport := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/transport=%v", operation, transport), func(t *testing.T) {
				logs.Reset()
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(400)
					_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"SECRET_BODY","access_token":"SECRET_TOKEN"}`)
				}))
				defer srv.Close()
				endpoint := srv.URL + "/" + operation + "?secret=SECRET_URL"
				client := srv.Client()
				if transport {
					client = &http.Client{Transport: secretTransport{}}
				}
				s := New("idp", Config{AuthURL: srv.URL, TokenURL: endpoint, UserInfoURL: endpoint, RevocationURL: endpoint, LogoutURL: endpoint, ClientSecret: "SECRET_CLIENT", AuthHeaderStyle: AuthHeaderStyleParams}, Options{HTTPClient: client})
				var err error
				switch operation {
				case "token":
					_, err = s.tokenRequest(context.Background(), url.Values{})
				case "userinfo":
					_, err = s.fetchUserInfo(context.Background(), "SECRET_ACCESS")
				case "discovery":
					_, err = Discover(context.Background(), client, endpoint)
					_ = New("idp", Config{IssuerURL: endpoint}, Options{HTTPClient: client})
				case "logout":
					err = s.Logout(context.Background(), nil)
				case "revoke":
					s.revoke(context.Background(), "SECRET_ACCESS")
				case "callback":
					u, c := startFlow(t, s)
					r := flowRequest(u, c)
					r.URL.RawQuery = "error=SECRET_CODE&error_description=SECRET_DESCRIPTION&state=" + u.Query().Get("state")
					w := httptest.NewRecorder()
					_, _, _ = s.Login(w, r)
					if strings.Contains(w.Body.String(), "SECRET") {
						t.Fatal(w.Body.String())
					}
				}
				if err != nil {
					if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), srv.URL) {
						t.Fatalf("unsafe returned error: %v", err)
					}
					w := httptest.NewRecorder()
					s.writeInternalError(w, 502, operation, "identity provider request failed", err)
					if w.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("cacheable error")
					}
				}
				if strings.Contains(logs.String(), "SECRET") || strings.Contains(logs.String(), srv.URL) {
					t.Fatalf("unsafe logs: %s", &logs)
				}
				if !transport && (operation == "token" || operation == "userinfo") && (!strings.Contains(logs.String(), "invalid_grant") || !strings.Contains(logs.String(), "upstream_status=400")) {
					t.Fatalf("missing safe diagnostics: %s", &logs)
				}
			})
		}
	}
}
