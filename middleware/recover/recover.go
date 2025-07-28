package recover

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/rakunlabs/ada"
)

type Recover struct {
	Logger     ada.Logger
	PrintStack bool
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
		Logger:     o.Logger,
		PrintStack: o.PrintStack,
	}
}

func Middleware(opts ...Option) func(next http.Handler) http.Handler {
	return New(opts...).Middleware
}

func (re *Recover) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				if r == http.ErrAbortHandler {
					panic(r)
				}
				err, ok := r.(error)
				if !ok {
					err = fmt.Errorf("%v", r)
				}

				if re.Logger != nil {
					re.Logger.Error("panic: " + err.Error())
				}
				if re.PrintStack {
					debug.PrintStack()
				}

				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write(fmt.Appendf(nil, "panic: %s", err.Error()))

				return
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// //////////////////////////////////////////////////////////////

type option struct {
	Logger     ada.Logger
	PrintStack bool
}

type Option func(*option)

func WithLogger(logger ada.Logger) Option {
	return func(o *option) {
		o.Logger = logger
	}
}

func WithPrintStack(printStack bool) Option {
	return func(o *option) {
		o.PrintStack = printStack
	}
}
