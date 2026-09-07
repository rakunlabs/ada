package recover

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"

	"github.com/felixge/httpsnoop"
)

type Recover struct {
	Logger     Logger
	PrintStack bool
	// ErrorHandler handles panics before the response is committed. A nil handler
	// sends a generic 500 response. Custom handlers are responsible for redaction.
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
}

func New(opts ...Option) *Recover {
	o := &option{
		Logger:     slog.Default(),
		PrintStack: true,
	}

	for _, opt := range opts {
		opt(o)
	}

	return &Recover{
		Logger:       o.Logger,
		PrintStack:   o.PrintStack,
		ErrorHandler: o.ErrorHandler,
	}
}

func Middleware(opts ...Option) func(next http.Handler) http.Handler {
	return New(opts...).Middleware
}

func (re *Recover) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		committed := false
		w = httpsnoop.Wrap(w, httpsnoop.Hooks{
			WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return func(code int) {
					if code == http.StatusSwitchingProtocols || code >= 200 && code <= 999 {
						committed = true
					}
					next(code)
				}
			},
			Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return func(b []byte) (int, error) {
					committed = true
					return next(b)
				}
			},
			Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
				return func() {
					committed = true
					next()
				}
			},
			Hijack: func(next httpsnoop.HijackFunc) httpsnoop.HijackFunc {
				return func() (net.Conn, *bufio.ReadWriter, error) {
					conn, rw, err := next()
					if err == nil {
						committed = true
					}
					return conn, rw, err
				}
			},
			ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
				return func(src io.Reader) (int64, error) {
					// ReadFrom can write directly, bypassing the Write hook, and
					// can panic after partial output. Treat it as committed on entry.
					committed = true
					return next(src)
				}
			},
		})
		defer func() {
			if value := recover(); value != nil {
				if value == http.ErrAbortHandler {
					panic(value)
				}
				err, ok := value.(error)
				if !ok {
					err = fmt.Errorf("%v", value)
				}

				if re.Logger != nil {
					re.Logger.Error("panic: " + err.Error())
				}
				if re.PrintStack {
					debug.PrintStack()
				}

				if committed {
					panic(http.ErrAbortHandler)
				}
				if re.ErrorHandler != nil {
					re.ErrorHandler(w, r, err)
				} else {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// //////////////////////////////////////////////////////////////

type option struct {
	Logger       Logger
	PrintStack   bool
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
}

type Option func(*option)

func WithLogger(logger Logger) Option {
	return func(o *option) {
		o.Logger = logger
	}
}

func WithPrintStack(printStack bool) Option {
	return func(o *option) {
		o.PrintStack = printStack
	}
}

// WithErrorHandler replaces the generic 500 response for panics before the
// response is committed. The handler receives the original error (or a string
// representation of a non-error panic) and is responsible for redacting it.
// A nil handler uses the default response.
func WithErrorHandler(handler func(http.ResponseWriter, *http.Request, error)) Option {
	return func(o *option) {
		o.ErrorHandler = handler
	}
}

// //////////////////////////////////////////////////////////////

type Logger interface {
	Error(msg string, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	Debug(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
}
