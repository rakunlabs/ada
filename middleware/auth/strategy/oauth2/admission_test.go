package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

func TestFlowSourceCannotExhaustStore(t *testing.T) {
	s, calls := genericStrategy(t)
	for i := range 4097 {
		r := httptest.NewRequest("GET", "https://app.example/login", nil)
		r.RemoteAddr = fmt.Sprintf("192.0.2.1:%d", 10000+i)
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.%d.%d", i/256, i%256))
		r.Header.Set("X-Real-IP", fmt.Sprintf("203.0.113.%d", i%256))
		r.Header.Set("True-Client-IP", fmt.Sprintf("203.0.114.%d", i%256))
		w := httptest.NewRecorder()
		_, _, _ = s.Login(w, r) // Discard every cookie, as an attacker can.
		if i < 10 {
			if w.Code != 307 {
				t.Fatalf("admitted status=%d", w.Code)
			}
		} else if w.Code != 429 || len(w.Result().Cookies()) != 0 || w.Header().Get("Location") != "" || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"error":"flow_source_full"`) {
			t.Fatalf("quota response=%d %s", w.Code, w.Body)
		}
	}
	if got := len(s.flows.(*memoryFlowStore).flows); got != 10 {
		t.Fatalf("pending=%d", got)
	}
	r := httptest.NewRequest("GET", "https://app.example/login", nil)
	r.RemoteAddr = "192.0.2.2:1234"
	w := httptest.NewRecorder()
	_, _, _ = s.Login(w, r)
	if w.Code != 307 || calls.Load() != 0 {
		t.Fatal("one source blocked another or reached upstream")
	}
}

func TestFlowSourceNormalizationAndTrust(t *testing.T) {
	for _, tt := range []struct {
		name       string
		peers      []string
		forwarded  []string
		trusted    []string
		unsafe     bool
		wantSecond int
	}{
		{"IPv4 ports and mapped", []string{"192.0.2.1:123", "[::ffff:192.0.2.1]:456"}, nil, nil, false, 429},
		{"IPv6 canonical", []string{"[2001:db8::1]:123", "[2001:0db8:0:0:0:0:0:1]:456"}, nil, nil, false, 429},
		{"untrusted headers", []string{"192.0.2.1:123", "192.0.2.1:456"}, []string{"198.51.100.1", "198.51.100.2"}, []string{"10.0.0.0/8"}, false, 429},
		{"unsafe flag ignored", []string{"192.0.2.1:123", "192.0.2.1:456"}, []string{"198.51.100.1", "198.51.100.2"}, nil, true, 429},
		{"trusted clients", []string{"10.0.0.1:123", "10.0.0.1:456"}, []string{"198.51.100.1", "198.51.100.2"}, []string{"10.0.0.0/8"}, false, 307},
		{"trusted chain ignores spoofed left", []string{"10.0.0.1:123", "10.0.0.2:456"}, []string{"203.0.113.1, 198.51.100.1, 10.1.1.1", "203.0.113.2, 198.51.100.1, 10.1.1.2"}, []string{"10.0.0.0/8"}, false, 429},
		{"malformed forwarding shares peer", []string{"10.0.0.1:123", "10.0.0.1:456"}, []string{"bad-one", "bad-two"}, []string{"10.0.0.0/8"}, false, 429},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := New("idp", Config{AuthURL: "https://idp.example/authorize"}, Options{CallbackBaseURL: "https://app.example", FlowMaxPendingPerSource: 1, TrustedProxies: tt.trusted, UnsafeTrustAllForwardedHeaders: tt.unsafe})
			for i, peer := range tt.peers {
				r := httptest.NewRequest("GET", "https://app.example/login", nil)
				r.RemoteAddr = peer
				if tt.forwarded != nil {
					r.Header.Set("X-Forwarded-For", tt.forwarded[i])
				}
				w := httptest.NewRecorder()
				_, _, _ = s.Login(w, r)
				want := 307
				if i == 1 {
					want = tt.wantSecond
				}
				if w.Code != want {
					t.Fatalf("request %d: status=%d want=%d body=%s", i, w.Code, want, w.Body)
				}
			}
		})
	}
	s := New("idp", Config{AuthURL: "https://idp.example/authorize"}, Options{CallbackBaseURL: "https://app.example", TrustedProxies: []string{"bad CIDR"}})
	w := httptest.NewRecorder()
	_, _, _ = s.Login(w, httptest.NewRequest("GET", "https://app.example/login", nil))
	if w.Code != 503 || len(s.flows.(*memoryFlowStore).flows) != 0 {
		t.Fatal("invalid proxy policy admitted a flow")
	}
}

func TestFlowSourceQuotaAtomicAndReleased(t *testing.T) {
	m := &memoryFlowStore{flows: make(map[string]FlowData)}
	f := FlowData{Source: "source", SourceLimit: 3, ExpiresAt: time.Now().Add(time.Hour)}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := m.Save(context.Background(), fmt.Sprint(i), f)
			if err == nil {
				admitted.Add(1)
			} else if !errors.Is(err, ErrFlowSourceFull) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 3 || len(m.flows) != 3 {
		t.Fatal("non-atomic source admission")
	}
	for k := range m.flows {
		if _, err := m.Consume(context.Background(), k); err != nil {
			t.Fatal(err)
		}
		break
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Save(ctx, "cancelled", f); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(m.flows) != 2 {
		t.Fatal("cancelled save leaked quota")
	}
	if err := m.Save(context.Background(), "replacement", f); err != nil {
		t.Fatal(err)
	}
	for k, v := range m.flows {
		v.ExpiresAt = time.Now()
		m.flows[k] = v
	}
	for i := range 3 {
		if err := m.Save(context.Background(), fmt.Sprintf("fresh-%d", i), f); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.flows) != 3 {
		t.Fatal("expiry did not release quota/prune entries")
	}
}

type admissionCaptureStore struct {
	FlowStore
	saved FlowData
}

func (s *admissionCaptureStore) Save(ctx context.Context, key string, f FlowData) error {
	s.saved = f
	return s.FlowStore.Save(ctx, key, f)
}

func TestFlowSourcePassedToInjectedStoreNotCallbackBinding(t *testing.T) {
	s, _ := genericStrategy(t)
	capture := &admissionCaptureStore{FlowStore: s.flows}
	s.flows = capture
	s.opts.FlowMaxPendingPerSource = 2
	u, c := startFlow(t, s)
	if len(capture.saved.Source) != 64 || capture.saved.SourceLimit != 2 {
		t.Fatalf("admission metadata=%+v", capture.saved)
	}
	r := flowRequest(u, c)
	r.RemoteAddr = "203.0.113.99:1234" // Mobile client changed networks.
	w := httptest.NewRecorder()
	id, outcome, err := s.Login(w, r)
	if err != nil || outcome != strategy.OutcomeContinue || id == nil {
		t.Fatalf("network change blocked callback: %d %s", w.Code, w.Body)
	}
}
