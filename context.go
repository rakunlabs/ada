package ada

import (
	"context"
	"net/http"
	"sync"
)

type contextKey string

const (
	CtxKey contextKey = "ada"
)

type Context struct {
	V map[string]any

	m sync.Mutex
}

func NewContext(r *http.Request) (*Context, *http.Request) {
	// set adaCtx value
	adaCtx := &Context{
		V: make(map[string]any),
	}

	ctx := context.WithValue(r.Context(), CtxKey, adaCtx)
	r = r.WithContext(ctx)

	return adaCtx, r
}

func (t *Context) Set(key string, value any) {
	t.m.Lock()
	defer t.m.Unlock()

	t.V[key] = value
}

func (t *Context) Get(key string) (any, bool) {
	t.m.Lock()
	defer t.m.Unlock()

	value, ok := t.V[key]

	return value, ok
}

func GetContext(r *http.Request) (*Context, bool) {
	ada, ok := r.Context().Value(CtxKey).(*Context)

	return ada, ok
}
