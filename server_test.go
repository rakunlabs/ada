package ada

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

var _ string = ListenerAddrContextKey

// startTestServer boots a server on an ephemeral port and returns its base URL
// plus the channel carrying Start's return value.
func startTestServer(t *testing.T, s *Server, opts ...OptionStart) (string, <-chan error) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start(addr, opts...) }()

	// Wait for the port to accept connections.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()

			return "http://" + addr, errCh
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf("server did not come up on %s", addr)

	return "", errCh
}

// TestServer_ShutdownTimeoutIsApplied guards the bug where New() dropped the
// configured shutdown timeout on the floor, leaving s.shutdownTimeout at zero.
// Every Stop() then created an already-expired context: there was no drain
// window at all and Stop always returned "context deadline exceeded".
func TestServer_ShutdownTimeoutIsApplied(t *testing.T) {
	t.Run("option is stored", func(t *testing.T) {
		s := New(WithShutdownTimeout(3 * time.Second))
		if s.shutdownTimeout != 3*time.Second {
			t.Errorf("shutdownTimeout = %v, want %v", s.shutdownTimeout, 3*time.Second)
		}
	})

	t.Run("default is stored", func(t *testing.T) {
		s := New()
		if s.shutdownTimeout != DefaultShutdownTimeout {
			t.Errorf("shutdownTimeout = %v, want %v", s.shutdownTimeout, DefaultShutdownTimeout)
		}
	})

	t.Run("in-flight request is allowed to finish", func(t *testing.T) {
		release := make(chan struct{})
		s := New(WithShutdownTimeout(5 * time.Second))
		s.GET("/slow", func(w http.ResponseWriter, r *http.Request) {
			<-release
			_, _ = w.Write([]byte("done"))
		})

		base, errCh := startTestServer(t, s)

		respCh := make(chan string, 1)
		go func() {
			resp, err := http.Get(base + "/slow")
			if err != nil {
				respCh <- "error: " + err.Error()

				return
			}
			body, readErr := io.ReadAll(resp.Body)
			closeErr := resp.Body.Close()
			if readErr != nil {
				respCh <- "error reading body: " + readErr.Error()

				return
			}
			if closeErr != nil {
				respCh <- "error closing body: " + closeErr.Error()

				return
			}
			respCh <- string(body)
		}()

		// Give the request time to reach the handler, then shut down.
		time.Sleep(100 * time.Millisecond)

		stopped := make(chan error, 1)
		go func() { stopped <- s.Stop() }()

		// Shutdown must still be draining, not already expired.
		time.Sleep(100 * time.Millisecond)
		close(release)

		if err := <-stopped; err != nil {
			t.Errorf("Stop returned %v, want nil (the request should have drained)", err)
		}
		if got := <-respCh; got != "done" {
			t.Errorf("in-flight response = %q, want %q", got, "done")
		}
		if err := <-errCh; err != nil {
			t.Errorf("Start returned %v", err)
		}
	})
}

// TestServer_ShutdownDeadlineForceClosesConnections guards the bug where a
// Stop that ran out of drain time returned the error and gave up: Shutdown
// leaves active connections open by design, and start's deferred cleanup then
// nils s.server/s.listener, so no caller could ever force them shut. The
// listener and the stuck connection stayed alive for the process lifetime.
func TestServer_ShutdownDeadlineForceClosesConnections(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})

	s := New(WithShutdownTimeout(100 * time.Millisecond))
	s.GET("/block", func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write([]byte("late"))
	})

	base, errCh := startTestServer(t, s)
	addr := strings.TrimPrefix(base, "http://")

	// A dedicated transport keeps this connection out of the shared pool, so
	// the only thing that can end the request is the server closing it.
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	reqErr := make(chan error, 1)
	go func() {
		resp, err := client.Get(base + "/block")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			err = resp.Body.Close()
			if err == nil {
				err = errors.New("request completed instead of being force-closed")
			}
		}
		reqErr <- err
	}()

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("handler was never entered")
	}

	stopErr := s.Stop()
	if stopErr == nil {
		close(release)
		t.Fatal("Stop returned nil, want the drain-deadline error")
	}
	if !errors.Is(stopErr, context.DeadlineExceeded) {
		t.Errorf("Stop error = %v, want it to wrap context.DeadlineExceeded", stopErr)
	}

	// The blocked connection must actually be gone, not merely un-drained.
	select {
	case err := <-reqErr:
		if err == nil {
			t.Error("in-flight connection was not closed by the forced shutdown")
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("in-flight connection still open after the shutdown deadline expired")
	}

	// The listener must be closed too.
	if conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond); err == nil {
		_ = conn.Close()
		close(release)
		t.Fatalf("listener on %s still accepting after forced shutdown", addr)
	}

	close(release)

	if err := <-errCh; err != nil {
		t.Fatalf("Start returned %v, want nil after a forced shutdown", err)
	}

	// And the Server must be reusable.
	base, errCh = startTestServer(t, s)

	resp, err := http.Get(base + "/ping")
	if err != nil {
		t.Fatalf("restart after forced shutdown: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 from the restarted server", resp.StatusCode)
	}

	if err := s.Stop(); err != nil {
		t.Fatalf("Stop after restart: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Start after restart returned %v", err)
	}
}

// TestServer_DoubleStartDoesNotDeadlock guards the bug where the early return
// on ErrAlreadyStarted kept the mutex held, so every later Stop/Start blocked
// forever.
func TestServer_DoubleStartDoesNotDeadlock(t *testing.T) {
	s := New()
	s.GET("/", func(w http.ResponseWriter, r *http.Request) {})

	base, errCh := startTestServer(t, s)

	if err := s.Start(base); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start = %v, want ErrAlreadyStarted", err)
	}

	done := make(chan error, 1)
	go func() { done <- s.Stop() }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Stop returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop deadlocked after a rejected second Start")
	}

	if err := <-errCh; err != nil {
		t.Errorf("Start returned %v", err)
	}
}

// TestServer_StopBeforeStart pins that Stop on a server that was never started
// is a no-op rather than a nil-pointer dereference.
func TestServer_StopBeforeStart(t *testing.T) {
	s := New()

	if err := s.Stop(); err != nil {
		t.Errorf("Stop before Start = %v, want nil", err)
	}
	if err := s.Stop(); err != nil {
		t.Errorf("second Stop = %v, want nil", err)
	}
}

func TestServerListenerAddressContextCompatibility(t *testing.T) {
	s := New()
	s.GET("/", func(w http.ResponseWriter, r *http.Request) {
		private, privateOK := r.Context().Value(listenerAddrContextKey).(net.Addr)
		exported, exportedOK := r.Context().Value(ListenerAddrContextKey).(net.Addr)
		legacy, legacyOK := r.Context().Value("listener_addr").(net.Addr)
		if !privateOK || !exportedOK || !legacyOK ||
			private.String() != exported.String() || exported.String() != legacy.String() {
			http.Error(w, "listener address context mismatch", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})

	//nolint:staticcheck // SA1029: intentionally seed the legacy public string key to test compatibility.
	baseContext := context.WithValue(context.Background(), ListenerAddrContextKey, "colliding value")
	base, errCh := startTestServer(t, s, WithBaseContext(baseContext))
	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close response: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Start: %v", err)
	}
}

// TestServer_StopRacingStartup guards the panic where Stop read s.listener
// before start() had assigned it. Reachable in normal use whenever the context
// passed to StartWithContext is cancelled during startup.
func TestServer_StopRacingStartup(t *testing.T) {
	for range 50 {
		s := New()
		s.GET("/", func(w http.ResponseWriter, r *http.Request) {})

		ctx, cancel := context.WithCancel(context.Background())

		errCh := make(chan error, 1)
		go func() { errCh <- s.StartWithContext(ctx, "127.0.0.1:0") }()
		go func() { _ = s.Stop() }()

		cancel()

		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
			t.Fatal("Start did not return after Stop raced startup")
		}
	}
}

// TestServer_RestartAfterStop pins that a stopped server can be started again,
// which requires start's cleanup to have reset every guarded field.
func TestServer_RestartAfterStop(t *testing.T) {
	s := New()
	s.GET("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	})

	for range 2 {
		base, errCh := startTestServer(t, s)

		resp, err := http.Get(base + "/ping")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close response body: %v", err)
		}

		if string(body) != "pong" {
			t.Fatalf("body = %q, want %q", body, "pong")
		}

		if err := s.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("Start: %v", err)
		}
	}
}

// TestServer_OldContextCannotStopRestart pins that the cancellation callback
// from a completed run is deregistered before the Server becomes reusable.
func TestServer_OldContextCannotStopRestart(t *testing.T) {
	s := New()
	s.GET("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	})

	oldCtx, cancelOld := context.WithCancel(context.Background())
	_, firstErr := startTestServer(t, s, WithContext(oldCtx))

	if err := s.Stop(); err != nil {
		t.Fatalf("stop first run: %v", err)
	}
	if err := <-firstErr; err != nil {
		t.Fatalf("first run: %v", err)
	}

	base, secondErr := startTestServer(t, s)

	// This context belonged to the completed first run. Cancelling it must
	// not call Stop on the second run.
	cancelOld()

	resp, err := http.Get(base + "/ping")
	if err != nil {
		t.Fatalf("second run stopped by old context: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}

	if string(body) != "pong" {
		t.Fatalf("body = %q, want %q", body, "pong")
	}

	if err := s.Stop(); err != nil {
		t.Fatalf("stop second run: %v", err)
	}
	if err := <-secondErr; err != nil {
		t.Fatalf("second run: %v", err)
	}
}
