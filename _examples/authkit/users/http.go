package users

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/authz"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
)

// Fresh re-reads the signed-in user on every request and replaces the
// identity with the current one, keeping the scopes, claims and provider
// the request was authenticated with. A deleted or disabled user gets 401;
// a user whose roles changed is authorized by the new roles at once.
//
// Place it right after Auth.Require. An identity that was issued for a local
// user (IsLocal) is refused once that user is disabled or deleted. Other
// identities (SSO, an API key, an external bearer token) pass through
// unchanged when passthrough is true and are refused otherwise.
func (s *Service) Fresh(passthrough bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := identity.FromContext(r.Context())
			if id == nil {
				next.ServeHTTP(w, r)

				return
			}

			u, err := s.current(r.Context(), id)
			switch {
			case errors.Is(err, errForeign):
				if passthrough {
					next.ServeHTTP(w, r)

					return
				}

				writeError(w, http.StatusUnauthorized, "unauthorized", "not a local account")

				return
			case errors.Is(err, ErrNotFound):
				writeError(w, http.StatusUnauthorized, "unauthorized", "the account is disabled or gone")

				return
			case err != nil:
				slog.Error("users: load user", "error", err.Error())
				writeError(w, http.StatusServiceUnavailable, "unavailable", "cannot load the user")

				return
			}

			next.ServeHTTP(w, r.WithContext(identity.WithContext(r.Context(), s.refresh(id, u))))
		})
	}
}

// errForeign marks an identity that is not one of this directory's users.
var errForeign = errors.New("users: not a local identity")

// current resolves id to its user. A local identity whose user is gone or
// disabled is ErrNotFound; an identity that was never local is errForeign.
//
// "Local" is read from the identity itself (ClaimLocal) and not from the
// store: a deleted user is absent from the store, and asking it would turn
// the deletion into a pass.
func (s *Service) current(ctx context.Context, id *identity.Identity) (*User, error) {
	u, err := s.Current(ctx, id)
	if !errors.Is(err, ErrNotFound) || IsLocal(id) {
		return u, err
	}

	// Not marked local: foreign, unless the subject is a (disabled) user of
	// ours whose identity predates the marker.
	if _, lookup := s.store.GetUser(ctx, id.Subject); errors.Is(lookup, ErrNotFound) {
		return nil, errForeign
	}

	return nil, ErrNotFound
}

// refresh merges the current user into the identity a request carries.
func (s *Service) refresh(id *identity.Identity, u *User) *identity.Identity {
	current := s.Identity(u)
	current.Scopes = slices.Clone(id.Scopes)
	current.Provider = id.Provider
	current.IssuedAt = id.IssuedAt
	current.ExpiresAt = id.ExpiresAt

	for k, v := range id.Claims {
		if _, ok := current.Claims[k]; !ok {
			current.Claims[k] = v
		}
	}

	return current
}

// IdentityHook is an oauthserver.Hooks.Identity that keeps tokens in step
// with the user: a disabled or deleted user's tokens stop working, and a
// token acts with the user's current roles. Tokens of identities that are
// not local users (SSO) are left as they were issued.
func (s *Service) IdentityHook() func(context.Context, *oauthserver.Token) (*identity.Identity, error) {
	return func(ctx context.Context, t *oauthserver.Token) (*identity.Identity, error) {
		if t.Identity == nil {
			return nil, oauthserver.ErrAccessDenied
		}

		u, err := s.current(ctx, t.Identity)
		switch {
		case errors.Is(err, errForeign):
			return t.Identity, nil
		case errors.Is(err, ErrNotFound):
			return nil, oauthserver.ErrAccessDenied
		case err != nil:
			return nil, err
		}

		return s.refresh(t.Identity, u), nil
	}
}

// SessionOnly refuses requests authenticated with an OAuth or personal
// access token. Account and user management sit behind it: a token approved
// for an MCP client must not be able to reset passwords or promote users,
// even when its owner could.
func SessionOnly() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if oauthserver.Info(identity.FromContext(r.Context())) != nil {
				writeError(w, http.StatusForbidden, "forbidden", "sign in with a browser session to do this")

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// sameOrigin refuses state-changing requests a browser sends on behalf of
// another site. Lax cookies still go out with a form post from a sibling
// subdomain; Sec-Fetch-Site and a JSON content type close that hole.
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			switch r.Header.Get("Sec-Fetch-Site") {
			case "", "same-origin", "none":
			default:
				writeError(w, http.StatusForbidden, "forbidden", "cross-site request refused")

				return
			}

			if r.ContentLength != 0 && !isJSON(r.Header.Get("Content-Type")) {
				writeError(w, http.StatusUnsupportedMediaType, "invalid", "send application/json")

				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func isJSON(ct string) bool {
	mt, _, _ := strings.Cut(ct, ";")

	return strings.EqualFold(strings.TrimSpace(mt), "application/json")
}

// Permission is an authz.Requirement satisfied by holding perm through a
// role. Use it with authz.Require, authz.Any and authz.All.
func (s *Service) Permission(perm string) authz.Requirement {
	return authz.RequirementFunc{
		Fn:   func(id *identity.Identity) bool { return s.Can(id, perm) },
		Text: "permission " + perm,
	}
}

// RequirePermission guards a route by permission: 401 when nobody is signed
// in, 403 when the user's roles do not grant perm.
func (s *Service) RequirePermission(perm string) func(http.Handler) http.Handler {
	return authz.Require(s.Permission(perm))
}

// ////////////////////////////////////////////////////////////////////////////
// HTTP API

// Mux is the subset of *ada.Mux the API registers routes on.
type Mux interface {
	HandleWithMethod(method, pattern string, handler http.HandlerFunc, mw ...func(http.Handler) http.Handler)
}

// MountSelf registers the signed-in user's own endpoints under prefix,
// e.g. "/api/v1/account". mw must authenticate (Auth.Require, Fresh).
//
//	GET  {prefix}           the current user and permissions
//	PUT  {prefix}           change name and email
//	POST {prefix}/password  change password {current, password}
//
// Requests authenticated with an OAuth or personal token are refused
// (SessionOnly), and state-changing requests must be same-origin JSON.
func (s *Service) MountSelf(mux Mux, prefix string, mw ...func(http.Handler) http.Handler) {
	prefix = strings.TrimSuffix(prefix, "/")
	mw = append(slices.Clone(mw), SessionOnly(), sameOrigin)

	mux.HandleWithMethod(http.MethodGet, prefix, s.handleSelf, mw...)
	mux.HandleWithMethod(http.MethodPut, prefix, s.handleSelfUpdate, mw...)
	mux.HandleWithMethod(http.MethodPost, prefix+"/password", s.handleSelfPassword, mw...)
}

// MountAdmin registers user management under prefix, e.g.
// "/api/v1/admin/users". mw must authenticate; reads need users:read and
// writes users:write on top of it.
//
//	GET    {prefix}         list users
//	POST   {prefix}         create {username, password, name, email, roles}
//	GET    {prefix}/roles   available roles with permissions
//	GET    {prefix}/{id}    one user
//	PATCH  {prefix}/{id}    update any of the fields, or password
//	DELETE {prefix}/{id}    delete
//
// Like MountSelf it accepts browser sessions only and same-origin JSON. An
// actor may only give roles whose permissions they hold, and may not change
// an account that holds permissions they lack.
func (s *Service) MountAdmin(mux Mux, prefix string, mw ...func(http.Handler) http.Handler) {
	prefix = strings.TrimSuffix(prefix, "/")
	mw = append(slices.Clone(mw), SessionOnly(), sameOrigin)

	read := append(slices.Clone(mw), s.RequirePermission(PermUsersRead))
	write := append(slices.Clone(mw), s.RequirePermission(PermUsersWrite))

	mux.HandleWithMethod(http.MethodGet, prefix, s.handleList, read...)
	mux.HandleWithMethod(http.MethodPost, prefix, s.handleCreate, write...)
	mux.HandleWithMethod(http.MethodGet, prefix+"/roles", s.handleRoles, read...)
	mux.HandleWithMethod(http.MethodGet, prefix+"/{id}", s.handleGet, read...)
	mux.HandleWithMethod(http.MethodPatch, prefix+"/{id}", s.handleUpdate, write...)
	mux.HandleWithMethod(http.MethodDelete, prefix+"/{id}", s.handleDelete, write...)
}

// SelfView is what GET {self} returns.
type SelfView struct {
	*User
	Permissions []string `json:"permissions"`
	HasPassword bool     `json:"has_password"`
	Provider    string   `json:"provider,omitempty"`
}

func (s *Service) self(w http.ResponseWriter, r *http.Request) (*User, bool) {
	u, err := s.current(r.Context(), identity.FromContext(r.Context()))
	if errors.Is(err, errForeign) {
		err = ErrNotFound
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "not signed in as a local user")
		} else {
			writeStoreError(w, err)
		}

		return nil, false
	}

	return u, true
}

func (s *Service) handleSelf(w http.ResponseWriter, r *http.Request) {
	u, ok := s.self(w, r)
	if !ok {
		return
	}

	writeJSON(w, http.StatusOK, SelfView{
		User:        u,
		Permissions: s.Permissions(u.Roles),
		HasPassword: u.HasPassword(),
		Provider:    identity.FromContext(r.Context()).Provider,
	})
}

func (s *Service) handleSelfUpdate(w http.ResponseWriter, r *http.Request) {
	u, ok := s.self(w, r)
	if !ok {
		return
	}

	var in struct {
		Name  *string `json:"name"`
		Email *string `json:"email"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	updated, err := s.Update(r.Context(), u.ID, UpdateRequest{Name: in.Name, Email: in.Email})
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, updated)
}

func (s *Service) handleSelfPassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.self(w, r)
	if !ok {
		return
	}

	var in struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	if err := s.ChangePassword(r.Context(), u.ID, in.Current, in.Password); err != nil {
		writeStoreError(w, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, list)
}

func (s *Service) handleRoles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Roles())
}

func (s *Service) handleGet(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, u)
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	var in CreateRequest
	if !readJSON(w, r, &in) {
		return
	}

	u, err := s.CreateAs(r.Context(), identity.FromContext(r.Context()), in)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusCreated, u)
}

func (s *Service) handleUpdate(w http.ResponseWriter, r *http.Request) {
	var in UpdateRequest
	if !readJSON(w, r, &in) {
		return
	}

	u, err := s.UpdateAs(r.Context(), identity.FromContext(r.Context()), r.PathValue("id"), in)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, u)
}

func (s *Service) handleDelete(w http.ResponseWriter, r *http.Request) {
	if id := identity.FromContext(r.Context()); id != nil && id.Subject == r.PathValue("id") {
		writeError(w, http.StatusBadRequest, "invalid", "you cannot delete yourself")

		return
	}

	if err := s.DeleteAs(r.Context(), identity.FromContext(r.Context()), r.PathValue("id")); err != nil {
		writeStoreError(w, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", "invalid JSON")

		return false
	}

	return true
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such user")
	case errors.Is(err, ErrExists):
		writeError(w, http.StatusConflict, "exists", "username already taken")
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden", strings.TrimPrefix(err.Error(), ErrForbidden.Error()+": "))
	case errors.Is(err, ErrLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", ErrLastAdmin.Error())
	case errors.Is(err, ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid", strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
	default:
		slog.Error("users: store", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "server_error", "the request failed")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}
