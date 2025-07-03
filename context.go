package ada

import (
	"context"
	"net/http"
	"sync"
)

type contextKey string

const (
	AdaKey contextKey = "ada"
)

type Context struct {
	V map[string]any

	m sync.Mutex
}

func NewContext(r *http.Request) (*Context, *http.Request) {
	// set ada value
	ada := &Context{
		V: make(map[string]any),
	}

	ctx := context.WithValue(r.Context(), AdaKey, ada)
	r = r.WithContext(ctx)

	return ada, r
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
	ada, ok := r.Context().Value(AdaKey).(*Context)

	return ada, ok
}

func Set(r *http.Request, key string, value any) {
	ada, ok := GetContext(r)
	if !ok {
		return
	}

	ada.Set(key, value)
}

func Get(r *http.Request, key string) any {
	ada, ok := GetContext(r)
	if !ok {
		return nil
	}

	v, _ := ada.Get(key)

	return v
}
