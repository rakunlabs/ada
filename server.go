package ada

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var (
	DefaultShutdownTimeout = 10 * time.Second
	ErrAlreadyStarted      = errors.New("server started already")
)

type Server struct {
	*Mux
	server          *http.Server
	logger          Logger
	started         bool
	shutdownTimeout time.Duration
	network         string

	m sync.Mutex
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
		Mux:     NewMux(),
		logger:  opt.Logger,
		network: opt.Network,
	}
}

// Start starts the server with the given address.
//   - If the server fails to start, an error will be returned.
func (s *Server) Start(addr string) error {
	return s.start(addr, nil)
}

// StartWithContext starts the server with the given context and address.
//   - If the context is canceled, the server will be stopped.
//   - If the server fails to start, an error will be returned.
func (s *Server) StartWithContext(ctx context.Context, addr string) error {
	return s.start(addr, func() {
		if ctx != nil {
			context.AfterFunc(ctx, func() {
				_ = s.Stop()
			})
		}
	})
}

func (s *Server) start(addr string, fn func()) error {
	s.m.Lock()
	if s.started {
		return ErrAlreadyStarted
	}

	s.started = true
	s.m.Unlock()

	defer func() {
		s.m.Lock()
		s.started = false
		s.m.Unlock()
	}()

	s.server = &http.Server{
		Addr:    addr,
		Handler: h2c.NewHandler(s.Mux, &http2.Server{}),
	}

	listener, err := net.Listen(s.network, s.server.Addr)
	if err != nil {
		return fmt.Errorf("address cannot listen %s: %w", s.server.Addr, err)
	}

	if fn != nil {
		fn()
	}

	s.logger.Info("server started", "addr", s.server.Addr)

	if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}

func (s *Server) Stop() error {
	s.m.Lock()
	defer s.m.Unlock()

	if !s.started {
		return nil
	}

	s.logger.Warn("stopping server", "addr", s.server.Addr)

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	return nil
}
