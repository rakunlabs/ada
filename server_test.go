package ada

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

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
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
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
		resp.Body.Close()

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
