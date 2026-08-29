package auth_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

var errCloseStrategy = errors.New("close strategy")

type closableStrategy struct {
	closes atomic.Int32
}

func (*closableStrategy) Name() string { return "closable" }
func (*closableStrategy) Descriptor() strategy.Descriptor {
	return strategy.Descriptor{Name: "closable"}
}
func (*closableStrategy) Login(http.ResponseWriter, *http.Request) (*identity.Identity, strategy.Outcome, error) {
	return nil, strategy.OutcomeFailed, nil
}
func (*closableStrategy) Logout(context.Context, *identity.Identity) error { return nil }
func (s *closableStrategy) Close() error {
	s.closes.Add(1)
	return errCloseStrategy
}

type closableSecondFactor struct {
	closes atomic.Int32
}

func (*closableSecondFactor) Required(context.Context, *identity.Identity) (bool, error) {
	return false, nil
}
func (*closableSecondFactor) Verify(context.Context, *http.Request, *identity.Identity) error {
	return nil
}
func (s *closableSecondFactor) Close() error {
	s.closes.Add(1)
	return nil
}

func TestAuthCloseIsIdempotent(t *testing.T) {
	s := &closableStrategy{}
	sf := &closableSecondFactor{}
	a := auth.New(auth.Config{}).Strategy(s).WithSecondFactor(sf)

	for range 2 {
		if err := a.Close(); !errors.Is(err, errCloseStrategy) {
			t.Fatalf("close error = %v, want strategy error", err)
		}
	}
	if got := s.closes.Load(); got != 1 {
		t.Fatalf("strategy closes = %d, want 1", got)
	}
	if got := sf.closes.Load(); got != 1 {
		t.Fatalf("second-factor closes = %d, want 1", got)
	}
}

func TestAuthCloseIncludesDisplacedStrategies(t *testing.T) {
	removed := &closableStrategy{}
	current := &closableStrategy{}
	a := auth.New(auth.Config{}).Strategy(removed)

	a.Registry().Replace(current)

	if err := a.Close(); !errors.Is(err, errCloseStrategy) {
		t.Fatalf("Close error = %v, want strategy close error", err)
	}
	if got := removed.closes.Load(); got != 1 {
		t.Fatalf("removed strategy closes = %d, want 1", got)
	}
	if got := current.closes.Load(); got != 1 {
		t.Fatalf("current strategy closes = %d, want 1", got)
	}
}
