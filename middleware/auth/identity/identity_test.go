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
	// An empty role is not a satisfied requirement. A caller writing
	// id.HasRole(cfg.Role) with an unset config value must not be told yes.
	if id.HasRole("") {
		t.Errorf("empty role should be false")
	}
	if !id.HasScope("read") {
		t.Errorf("expected read scope")
	}
	if id.HasScope("delete") {
		t.Errorf("did not expect delete scope")
	}
	if id.HasScope("") {
		t.Errorf("empty scope should be false")
	}

	var nilID *Identity
	if nilID.HasRole("admin") || nilID.HasScope("read") {
		t.Errorf("nil identity should hold nothing")
	}
}

func TestHasAnyAll(t *testing.T) {
	id := &Identity{Roles: []string{"admin"}, Scopes: []string{"read"}}

	if !id.HasAnyRole("ghost", "admin") {
		t.Errorf("expected any-role match")
	}
	if id.HasAnyRole("ghost") {
		t.Errorf("did not expect any-role match")
	}
	if id.HasAllRoles("admin", "ghost") {
		t.Errorf("did not expect all-roles match")
	}
	if !id.HasAllRoles() {
		t.Errorf("empty all-roles should be vacuously true")
	}
	if !id.HasAnyScope("read", "write") {
		t.Errorf("expected any-scope match")
	}
	if !id.HasAllScopes("read") {
		t.Errorf("expected all-scopes match")
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
