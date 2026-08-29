package ada

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	DefaultShutdownTimeout   = 10 * time.Second
	DefaultReadHeaderTimeout = 10 * time.Second
	ErrAlreadyStarted        = errors.New("server started already")
	ErrListen                = errors.New("listen")

	ListenerAddrContextKey = "listener_addr"
)

type Server struct {
	*Mux
	logger          Logger
	shutdownTimeout time.Duration

	// Guarded by m. server and listener are published only once Serve is
	// about to run; Stop must not touch them before that. stopping records
	// a Stop that arrived while start was still binding, so start can back
	// out instead of serving a socket nobody wants.
	m          sync.Mutex
	server     *http.Server
	listener   net.Listener
	started    bool
	stopping   bool
	generation uint64
}

func NewWithFunc(ctx context.Context, fn func(ctx context.Context, mux *Mux) error, opts ...Option) (*Server, error) {
	s := New(opts...)

	if err := fn(ctx, s.Mux); err != nil {
		return nil, fmt.Errorf("mux handler: %w", err)
	}

	return s, nil
}

func New(opts ...Option) *Server {
	opt := getOption(option{
		ShutdownTimeout: DefaultShutdownTimeout,
	}, opts...)

	return &Server{
		Mux:             NewMux(),
		logger:          opt.Logger,
		shutdownTimeout: opt.ShutdownTimeout,
	}
}

// Start starts the server with the given address.
//   - If the server fails to start, an error will be returned.
func (s *Server) Start(addr string, opts ...OptionStart) error {
	return s.start(addr, opts...)
}

// StartWithContext starts the server with the given context and address.
//   - If the context is canceled, the server will be stopped.
//   - If the server fails to start, an error will be returned.
func (s *Server) StartWithContext(ctx context.Context, addr string, opts ...OptionStart) error {
	return s.start(addr, append(opts, WithContext(ctx))...)
}

func (s *Server) start(addr string, opts ...OptionStart) error {
	s.m.Lock()
	if s.started {
		// Unlock before returning: holding the mutex here deadlocked every
		// later Start/Stop on this Server.
		s.m.Unlock()

		return ErrAlreadyStarted
	}

	s.started = true
	s.stopping = false
	s.generation++
	generation := s.generation
	s.m.Unlock()

	defer func() {
		s.m.Lock()
		s.started = false
		s.server = nil
		s.listener = nil
		s.m.Unlock()
	}()

	opt := getOptionStart(optionStart{}, opts...)

	baseContext := opt.BaseContext
	if baseContext == nil {
		baseContext = context.Background()
	}

	listener, err := net.Listen(opt.Network, addr)
	if err != nil {
		return fmt.Errorf("address cannot listen %s: %w, %w", addr, ErrListen, err)
	}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)

	server := opt.HTTPServerFunc(
		&http.Server{
			ReadHeaderTimeout: opt.ReadHeaderTimeout,
			BaseContext: func(_ net.Listener) context.Context {
				return context.WithValue(baseContext, ListenerAddrContextKey, listener.Addr())
			},
			Protocols: protocols,
			Handler:   s.Mux,
		},
	)

	// Publish under the mutex; until this point Stop must not see them.
	s.m.Lock()
	stopping := s.stopping
	if !stopping {
		s.listener = listener
		s.server = server
	}
	s.m.Unlock()

	if stopping {
		// Stop arrived while we were still binding — honour it instead of
		// serving a listener nobody is going to shut down.
		return listener.Close()
	}

	if opt.Context != nil {
		stopAfter := context.AfterFunc(opt.Context, func() {
			if err := s.stopGeneration(generation); err != nil {
				s.logger.Error("error stopping server", "error", err)
			}
		})
		// A Server can be started again after Serve returns. Deregister this
		// run's callback before start's state cleanup makes the Server
		// reusable, otherwise cancelling an old context can stop a later run.
		defer stopAfter()
	}

	s.logger.Info("server started", "addr", listener.Addr().String())

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}

// Stop gracefully shuts the server down, waiting up to the configured
// shutdown timeout for in-flight requests to finish.
//   - Safe to call before Start, concurrently with Start, and more than once.
func (s *Server) Stop() error {
	return s.stopGeneration(0)
}

// stopGeneration stops the current run when generation is zero, or only the
// specified run otherwise. Context callbacks use the latter form so a delayed
// callback from a completed run cannot stop a restarted Server.
func (s *Server) stopGeneration(generation uint64) error {
	s.m.Lock()

	if !s.started || (generation != 0 && s.generation != generation) {
		s.m.Unlock()

		return nil
	}

	s.stopping = true
	server, listener, timeout := s.server, s.listener, s.shutdownTimeout
	s.m.Unlock()

	if server == nil {
		// Start is still binding; it will observe stopping and back out.
		return nil
	}

	if timeout <= 0 {
		timeout = DefaultShutdownTimeout
	}

	s.logger.Warn("stopping server", "addr", listener.Addr().String())

	// Shutdown runs WITHOUT the mutex: it blocks until connections drain,
	// and start's cleanup needs the mutex to mark the server stopped.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	return nil
}
