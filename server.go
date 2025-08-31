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
	ErrListen              = errors.New("listen")

	ListenerAddrContextKey = "listener_addr"
)

type Server struct {
	*Mux
	server          *http.Server
	logger          Logger
	started         bool
	shutdownTimeout time.Duration
	listener        net.Listener

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
		Mux:    NewMux(),
		logger: opt.Logger,
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
		return ErrAlreadyStarted
	}

	s.started = true
	s.m.Unlock()

	defer func() {
		s.m.Lock()
		s.started = false
		s.m.Unlock()
	}()

	opt := getOptionStart(optionStart{}, opts...)

	baseContext := opt.BaseContext
	if baseContext == nil {
		baseContext = context.Background()
	}

	var err error
	s.listener, err = net.Listen(opt.Network, addr)
	if err != nil {
		return fmt.Errorf("address cannot listen %s: %w, %w", addr, ErrListen, err)
	}

	s.server = opt.HTTPServerFunc(
		&http.Server{
			Handler: h2c.NewHandler(s.Mux, &http2.Server{}),
			BaseContext: func(_ net.Listener) context.Context {
				return context.WithValue(baseContext, ListenerAddrContextKey, s.listener.Addr())
			},
		},
	)

	if opt.Context != nil {
		context.AfterFunc(opt.Context, func() {
			err := s.Stop()
			if err != nil {
				s.logger.Error("error stopping server", "error", err)
			}
		})
	}

	s.logger.Info("server started", "addr", s.listener.Addr().String())

	if err := s.server.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	s.logger.Warn("stopping server", "addr", s.listener.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	return nil
}
