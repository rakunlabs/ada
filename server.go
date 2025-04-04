package ada

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rakunlabs/logi/logadapter"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var ShutdownTimeout = 10 * time.Second

type Server struct {
	Mux    *http.ServeMux
	server *http.Server
	logger logadapter.Adapter

	m sync.Mutex
}

func New(ctx context.Context, fn func(ctx context.Context, mux *http.ServeMux) error, opts ...Option) (*Server, error) {
	opt := getOption(option{}, opts...)

	mux := http.NewServeMux()

	if err := fn(ctx, mux); err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	return &Server{
		Mux:    mux,
		logger: opt.Logger,
	}, nil
}

func (s *Server) Start(addr string) error {
	s.server = &http.Server{ //nolint:gosec // skip check in service
		Addr:    addr,
		Handler: h2c.NewHandler(s.Mux, &http2.Server{}),
	}

	s.logger.Info("starting server", "addr", s.server.Addr)

	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

func (s *Server) Stop() error {
	s.m.Lock()
	defer s.m.Unlock()

	if s.server == nil {
		return nil
	}

	s.logger.Warn("stopping server", "addr", s.server.Addr)

	defer func() {
		s.server = nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	return nil
}
