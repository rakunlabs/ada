package identity

import (
	"context"
	"testing"
)

func TestHasRoleScope(t *testing.T) {
	id := &Identity{Roles: []string{"admin", "user"}, Scopes: []string{"read", "write"}}

	if !id.HasRole("admin") {
		t.Errorf("expected admin role")
	}
	if id.HasRole("ghost") {
		t.Errorf("did not expect ghost role")
	}
	if !id.HasRole("") {
		t.Errorf("empty role should be true")
	}
	if !id.HasScope("read") {
		t.Errorf("expected read scope")
	}
	if id.HasScope("delete") {
		t.Errorf("did not expect delete scope")
	}
}

func TestClaim(t *testing.T) {
	id := &Identity{
		Claims: map[string]any{
			"tenant_id": "acme",
			"count":     int(7),
		},
	}

	if v := Claim[string](id, "tenant_id"); v != "acme" {
		t.Errorf("got tenant_id = %q", v)
	}
	if v := Claim[int](id, "count"); v != 7 {
		t.Errorf("got count = %d", v)
	}
	if v := Claim[string](id, "missing"); v != "" {
		t.Errorf("missing should yield zero, got %q", v)
	}
	if v := Claim[string](nil, "tenant_id"); v != "" {
		t.Errorf("nil identity should yield zero, got %q", v)
	}
}

func TestContext(t *testing.T) {
	id := &Identity{Subject: "alice"}
	ctx := WithContext(context.Background(), id)

	got := FromContext(ctx)
	if got == nil || got.Subject != "alice" {
		t.Errorf("FromContext returned %+v", got)
	}

	if FromContext(context.Background()) != nil {
		t.Errorf("expected nil for empty context")
	}
}
