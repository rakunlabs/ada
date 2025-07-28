package ada

import (
	"context"
	"errors"
	"fmt"
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

	m sync.Mutex
}

func NewWithFunc(ctx context.Context, fn func(ctx context.Context, mux *Mux) error, opts ...Option) (*Server, error) {
	opt := getOption(option{
		ShutdownTimeout: DefaultShutdownTimeout,
	}, opts...)

	mux := NewMux()

	if err := fn(ctx, mux); err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	return &Server{
		Mux:    mux,
		logger: opt.Logger,
	}, nil
}

func New(opts ...Option) *Server {
	opt := getOption(option{
		ShutdownTimeout: DefaultShutdownTimeout,
	}, opts...)

	return &Server{
		Mux:    NewMux(),
		logger: opt.Logger,
	}
}

func (s *Server) Start(ctx context.Context, addr string) error {
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

	s.logger.Info("starting server", "addr", s.server.Addr)

	context.AfterFunc(ctx, func() {
		_ = s.Stop()
	})

	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to start server: %w", err)
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
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	return nil
}
