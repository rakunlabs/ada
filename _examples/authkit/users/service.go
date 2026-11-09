package users

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/password"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
)

// Config configures a Service.
type Config struct {
	// Roles defines the available roles and their permissions. Empty uses
	// DefaultRoles (admin with "*", user with nothing).
	Roles []Role `cfg:"roles"`

	// DefaultRoles are given to users created by signup or by an admin who
	// picks no role. Defaults to ["user"].
	DefaultRoles []string `cfg:"default_roles"`

	// AdminRole is the role that may never disappear: the last enabled user
	// holding it cannot be disabled, deleted or demoted. Defaults to
	// "admin". It must grant users:write.
	AdminRole string `cfg:"admin_role"`

	// MinPasswordLength defaults to 8.
	MinPasswordLength int `cfg:"min_password_length"`

	// Signup lets anyone create an account from the login page. Off by
	// default. FirstUserSignup is the bootstrap alternative.
	Signup bool `cfg:"signup"`

	// FirstUserSignup opens signup only while there are no users, and makes
	// that first user an administrator. On by default unless Bootstrap is
	// set; set DisableFirstUserSignup to turn it off.
	DisableFirstUserSignup bool `cfg:"disable_first_user_signup"`

	// Bootstrap creates an administrator on start when there are no users.
	Bootstrap Bootstrap `cfg:"bootstrap"`

	// ExternalLogin tells the service that users can sign in without a
	// password (SSO, passkey, LDAP). Without it an admin with no password
	// does not count towards the last-admin rule, so removing the last
	// admin's password is refused.
	ExternalLogin bool `cfg:"external_login"`

	// Hasher hashes passwords. Defaults to password.New() (PBKDF2).
	Hasher password.Hasher `cfg:"-" json:"-"`

	// Now replaces time.Now in tests.
	Now func() time.Time `cfg:"-" json:"-"`
}

// Bootstrap is the first administrator.
type Bootstrap struct {
	Username string `cfg:"username"`
	Password string `cfg:"password" log:"-"`
}

// Service manages users. It is safe for concurrent use.
type Service struct {
	cfg   Config
	store Store
	roles map[string]Role
	// empty caches "no users yet" so the login page does not count users on
	// every load once somebody exists.
	empty atomic.Bool

	// writeMu serializes changes that the last-admin rule and first-user
	// signup depend on, so two concurrent requests cannot both pass a
	// check that only one of them may. It covers one process; with several
	// replicas the store has to provide the same guarantee.
	writeMu sync.Mutex
}

// New validates cfg and returns a Service.
func New(cfg Config, store Store) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("users: nil store")
	}

	if len(cfg.Roles) == 0 {
		cfg.Roles = DefaultRoles()
	}
	if cfg.AdminRole == "" {
		cfg.AdminRole = RoleAdmin
	}
	if len(cfg.DefaultRoles) == 0 {
		cfg.DefaultRoles = []string{RoleUser}
	}
	if cfg.MinPasswordLength <= 0 {
		cfg.MinPasswordLength = 8
	}
	if cfg.Hasher == nil {
		cfg.Hasher = password.New()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	s := &Service{cfg: cfg, store: store, roles: map[string]Role{}}

	for _, r := range cfg.Roles {
		if r.Name == "" || strings.ContainsAny(r.Name, " \t\r\n,") {
			return nil, fmt.Errorf("users: invalid role name %q", r.Name)
		}
		if _, dup := s.roles[r.Name]; dup {
			return nil, fmt.Errorf("users: duplicate role %q", r.Name)
		}

		s.roles[r.Name] = r
	}

	admin, ok := s.roles[cfg.AdminRole]
	if !ok {
		return nil, fmt.Errorf("users: admin role %q is not defined", cfg.AdminRole)
	}
	if !slices.ContainsFunc(admin.Permissions, func(p string) bool { return Grants(p, PermUsersWrite) }) {
		return nil, fmt.Errorf("users: admin role %q must grant %s", cfg.AdminRole, PermUsersWrite)
	}

	for _, r := range cfg.DefaultRoles {
		if _, ok := s.roles[r]; !ok {
			return nil, fmt.Errorf("users: default role %q is not defined", r)
		}
	}

	s.empty.Store(true)

	return s, nil
}

// Store returns the underlying store.
func (s *Service) Store() Store { return s.store }

// Roles returns the configured roles.
func (s *Service) Roles() []Role { return slices.Clone(s.cfg.Roles) }

// Init creates the bootstrap administrator when there are no users yet.
// Call it once at start, after the store's tables exist.
func (s *Service) Init(ctx context.Context) error {
	n, err := s.store.CountUsers(ctx)
	if err != nil {
		return fmt.Errorf("users: count: %w", err)
	}

	if n > 0 {
		s.empty.Store(false)

		return nil
	}

	b := s.cfg.Bootstrap
	if b.Username == "" {
		if !s.firstUserSignup() {
			slog.Warn("users: no users exist and no bootstrap admin is configured; nobody can sign in")
		}

		return nil
	}

	if b.Password == "" {
		return fmt.Errorf("users: bootstrap.password is required with bootstrap.username")
	}

	if _, err := s.Create(ctx, CreateRequest{Username: b.Username, Password: b.Password, Roles: []string{s.cfg.AdminRole}}); err != nil {
		return fmt.Errorf("users: bootstrap admin: %w", err)
	}

	slog.Info("users: created bootstrap administrator", "username", b.Username)

	return nil
}

func (s *Service) firstUserSignup() bool {
	return !s.cfg.DisableFirstUserSignup && s.cfg.Bootstrap.Username == ""
}

// NoUsers reports whether no account exists yet. Cheap after the first user.
// A store error counts as "users exist", which keeps bootstrap signup shut.
func (s *Service) NoUsers(ctx context.Context) bool {
	if !s.empty.Load() {
		return false
	}

	n, err := s.store.CountUsers(ctx)
	if err != nil {
		return false
	}
	if n > 0 {
		s.empty.Store(false)

		return false
	}

	return true
}

// SignupOpen reports whether the login page should offer signup now.
func (s *Service) SignupOpen(ctx context.Context) bool {
	return s.cfg.Signup || (s.firstUserSignup() && s.NoUsers(ctx))
}

// ////////////////////////////////////////////////////////////////////////////
// permissions

// Permissions returns the permissions granted by roles.
func (s *Service) Permissions(roles []string) []string {
	var out []string

	for _, name := range roles {
		for _, p := range s.roles[name].Permissions {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}

	return out
}

// Can reports whether an identity holds perm through its roles.
func (s *Service) Can(id *identity.Identity, perm string) bool {
	if id == nil {
		return false
	}

	for _, name := range id.Roles {
		for _, p := range s.roles[name].Permissions {
			if Grants(p, perm) {
				return true
			}
		}
	}

	return false
}

// ////////////////////////////////////////////////////////////////////////////
// identity

// Identity.Claims keys set by Identity. ClaimLocal marks an identity that
// belongs to this directory: Fresh and IdentityHook refuse such an identity
// once its user is gone, instead of mistaking it for an SSO or API-key
// identity and letting it through.
const (
	ClaimUsername    = "username"
	ClaimPermissions = "permissions"
	ClaimLocal       = "ada_local_user"
)

// IsLocal reports whether id was issued for a user of a users.Service.
func IsLocal(id *identity.Identity) bool {
	if id == nil {
		return false
	}

	v, _ := id.Claims[ClaimLocal].(bool)

	return v
}

// Identity maps a user to the identity a session or token carries.
func (s *Service) Identity(u *User) *identity.Identity {
	// Attributes first, so a user attribute named "permissions" cannot
	// replace the computed permissions.
	claims := maps.Clone(u.Attributes)
	if claims == nil {
		claims = map[string]any{}
	}
	claims[ClaimUsername] = u.Username
	claims[ClaimPermissions] = s.Permissions(u.Roles)
	claims[ClaimLocal] = true

	return &identity.Identity{
		Subject:       u.ID,
		Name:          firstNonEmpty(u.Name, u.Username),
		Email:         u.Email,
		EmailVerified: false,
		Roles:         slices.Clone(u.Roles),
		Claims:        claims,
		IssuedAt:      s.cfg.Now(),
	}
}

// Current re-reads the user behind id. It returns ErrNotFound when the user
// is gone or disabled.
func (s *Service) Current(ctx context.Context, id *identity.Identity) (*User, error) {
	if id == nil || id.Subject == "" {
		return nil, ErrNotFound
	}

	u, err := s.store.GetUser(ctx, id.Subject)
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrNotFound
	}

	return u, nil
}

// ////////////////////////////////////////////////////////////////////////////
// local strategy

// Verifier is the strategy/local credential check.
func (s *Service) Verifier() local.Verifier {
	return func(ctx context.Context, username, pass string) (*identity.Identity, error) {
		u, err := s.store.GetUserByUsername(ctx, strings.TrimSpace(username))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}

		// An unknown user pays for a derivation too, so timing does not tell
		// which usernames exist.
		hash := password.Dummy
		if u != nil && u.HasPassword() {
			hash = u.PasswordHash
		}

		if err := s.cfg.Hasher.Verify(hash, pass); err != nil || u == nil || u.Disabled || !u.HasPassword() {
			return nil, local.ErrInvalidCredentials
		}

		if rh, ok := s.cfg.Hasher.(interface{ NeedsRehash(string) bool }); ok && rh.NeedsRehash(u.PasswordHash) {
			s.rehash(ctx, u.ID, u.PasswordHash, pass)
		}

		return s.Identity(u), nil
	}
}

// Registrar is the strategy/local signup handler. It refuses unless
// SignupOpen; the first user created through it becomes an administrator.
func (s *Service) Registrar() local.Registrar {
	return func(ctx context.Context, req local.RegisterRequest) (*identity.Identity, error) {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()

		if !s.SignupOpen(ctx) {
			return nil, fmt.Errorf("%w: signup is closed", local.ErrInvalidInput)
		}

		roles := s.cfg.DefaultRoles
		if s.firstUserSignup() && s.NoUsers(ctx) {
			roles = []string{s.cfg.AdminRole}
		}

		u, err := s.create(ctx, CreateRequest{
			Username: req.Username,
			Password: req.Password,
			Name:     req.Extras["name"],
			Email:    req.Extras["email"],
			Roles:    roles,
		})

		switch {
		case errors.Is(err, ErrExists):
			return nil, local.ErrUserExists
		case errors.Is(err, ErrInvalid):
			return nil, fmt.Errorf("%w: %s", local.ErrInvalidInput, strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
		case err != nil:
			return nil, err
		}

		return s.Identity(u), nil
	}
}

// rehash upgrades a password hash after a successful login. It re-reads the
// user under the write lock and writes only if the hash is still the one the
// login verified, so it cannot undo a concurrent disable, role change or
// password reset.
func (s *Service) rehash(ctx context.Context, id, verified, pass string) {
	h, err := s.cfg.Hasher.Hash(pass)
	if err != nil {
		return
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	u, err := s.store.GetUser(ctx, id)
	if err != nil || u.PasswordHash != verified {
		return
	}

	u.PasswordHash = h
	u.UpdatedAt = s.cfg.Now()

	if err := s.store.UpdateUser(ctx, u); err != nil {
		slog.Warn("users: rehash password", "error", err.Error())
	}
}

// ////////////////////////////////////////////////////////////////////////////
// management

// CreateRequest creates a user.
type CreateRequest struct {
	Username   string         `json:"username"`
	Password   string         `json:"password"`
	Name       string         `json:"name"`
	Email      string         `json:"email"`
	Roles      []string       `json:"roles"`
	Disabled   bool           `json:"disabled"`
	Attributes map[string]any `json:"attributes"`
}

// Create validates and stores a new user. An empty password creates a user
// who cannot sign in with a password (SSO-only).
func (s *Service) Create(ctx context.Context, req CreateRequest) (*User, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	return s.create(ctx, req)
}

func (s *Service) create(ctx context.Context, req CreateRequest) (*User, error) {
	username, err := s.validUsername(req.Username)
	if err != nil {
		return nil, err
	}

	roles := req.Roles
	if len(roles) == 0 {
		roles = s.cfg.DefaultRoles
	}
	if roles, err = s.validRoles(roles); err != nil {
		return nil, err
	}

	if err := validEmail(req.Email); err != nil {
		return nil, err
	}

	hash := ""
	if req.Password != "" {
		if hash, err = s.hash(req.Password); err != nil {
			return nil, err
		}
	}

	now := s.cfg.Now()
	u := &User{
		ID:           newID(),
		Username:     username,
		Name:         strings.TrimSpace(req.Name),
		Email:        strings.TrimSpace(req.Email),
		PasswordHash: hash,
		Roles:        roles,
		Disabled:     req.Disabled,
		Attributes:   maps.Clone(req.Attributes),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.store.CreateUser(ctx, u); err != nil {
		return nil, err
	}

	s.empty.Store(false)

	return u, nil
}

// UpdateRequest changes a user. Nil fields are left as they are.
type UpdateRequest struct {
	Username   *string         `json:"username,omitempty"`
	Name       *string         `json:"name,omitempty"`
	Email      *string         `json:"email,omitempty"`
	Roles      *[]string       `json:"roles,omitempty"`
	Disabled   *bool           `json:"disabled,omitempty"`
	Attributes *map[string]any `json:"attributes,omitempty"`
	// Password sets a new password; an empty string removes it.
	Password *string `json:"password,omitempty"`
}

// Update applies req to the user with id.
func (s *Service) Update(ctx context.Context, id string, req UpdateRequest) (*User, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	u, err := s.store.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}

	wasAdmin := s.activeAdmin(u)

	if req.Username != nil {
		if u.Username, err = s.validUsername(*req.Username); err != nil {
			return nil, err
		}
	}
	if req.Name != nil {
		u.Name = strings.TrimSpace(*req.Name)
	}
	if req.Email != nil {
		if err := validEmail(*req.Email); err != nil {
			return nil, err
		}
		u.Email = strings.TrimSpace(*req.Email)
	}
	if req.Roles != nil {
		if u.Roles, err = s.validRoles(*req.Roles); err != nil {
			return nil, err
		}
	}
	if req.Disabled != nil {
		u.Disabled = *req.Disabled
	}
	if req.Attributes != nil {
		u.Attributes = maps.Clone(*req.Attributes)
	}
	if req.Password != nil {
		u.PasswordHash = ""
		if *req.Password != "" {
			if u.PasswordHash, err = s.hash(*req.Password); err != nil {
				return nil, err
			}
		}
	}

	if wasAdmin && !s.activeAdmin(u) {
		if err := s.keepAnAdmin(ctx, u.ID); err != nil {
			return nil, err
		}
	}

	u.UpdatedAt = s.cfg.Now()

	if err := s.store.UpdateUser(ctx, u); err != nil {
		return nil, err
	}

	return u, nil
}

// Delete removes a user.
func (s *Service) Delete(ctx context.Context, id string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	u, err := s.store.GetUser(ctx, id)
	if err != nil {
		return err
	}

	if s.activeAdmin(u) {
		if err := s.keepAnAdmin(ctx, u.ID); err != nil {
			return err
		}
	}

	return s.store.DeleteUser(ctx, id)
}

// ChangePassword lets a user change their own password, proving the current
// one first.
func (s *Service) ChangePassword(ctx context.Context, id, current, next string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	u, err := s.store.GetUser(ctx, id)
	if err != nil {
		return err
	}

	if u.HasPassword() {
		if err := s.cfg.Hasher.Verify(u.PasswordHash, current); err != nil {
			return fmt.Errorf("%w: the current password is wrong", ErrInvalid)
		}
	}

	if u.PasswordHash, err = s.hash(next); err != nil {
		return err
	}
	u.UpdatedAt = s.cfg.Now()

	return s.store.UpdateUser(ctx, u)
}

// ErrForbidden refuses a change the acting user may not make.
var ErrForbidden = errors.New("users: not allowed")

// mayGrant reports whether actor may hand out every role in roles: each
// role's permissions must already be the actor's. Without this, anybody with
// users:write could make themselves admin.
func (s *Service) mayGrant(actor *identity.Identity, roles []string) bool {
	for _, name := range roles {
		for _, p := range s.roles[name].Permissions {
			if !s.Can(actor, p) {
				return false
			}
		}
	}

	return true
}

// mayManage reports whether actor may change the roles, password, status or
// identity of target. Accounts holding permissions the actor lacks (an
// administrator, seen from a user manager) are off limits: resetting their
// password is taking them over.
func (s *Service) mayManage(actor *identity.Identity, target *User) bool {
	return s.mayGrant(actor, target.Roles)
}

// CreateAs is Create on behalf of actor, who may only give roles whose
// permissions they hold.
func (s *Service) CreateAs(ctx context.Context, actor *identity.Identity, req CreateRequest) (*User, error) {
	roles := req.Roles
	if len(roles) == 0 {
		roles = s.cfg.DefaultRoles
	}

	if !s.mayGrant(actor, roles) {
		return nil, fmt.Errorf("%w: you cannot give a role with permissions you do not have", ErrForbidden)
	}

	return s.Create(ctx, req)
}

// UpdateAs is Update on behalf of actor. Changing a user the actor does not
// outrank, or giving roles beyond the actor's own permissions, is refused.
func (s *Service) UpdateAs(ctx context.Context, actor *identity.Identity, id string, req UpdateRequest) (*User, error) {
	u, err := s.store.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}

	if !s.mayManage(actor, u) {
		return nil, fmt.Errorf("%w: this account has permissions you do not have", ErrForbidden)
	}
	if req.Roles != nil && !s.mayGrant(actor, *req.Roles) {
		return nil, fmt.Errorf("%w: you cannot give a role with permissions you do not have", ErrForbidden)
	}

	return s.Update(ctx, id, req)
}

// DeleteAs is Delete on behalf of actor, with the same rule as UpdateAs.
func (s *Service) DeleteAs(ctx context.Context, actor *identity.Identity, id string) error {
	u, err := s.store.GetUser(ctx, id)
	if err != nil {
		return err
	}

	if !s.mayManage(actor, u) {
		return fmt.Errorf("%w: this account has permissions you do not have", ErrForbidden)
	}

	return s.Delete(ctx, id)
}

// activeAdmin reports whether u counts towards keeping the system
// administrable: enabled, holding the admin role, and able to sign in. An
// admin without a password counts only when Config.ExternalLogin says users
// can sign in some other way (SSO).
func (s *Service) activeAdmin(u *User) bool {
	return !u.Disabled && slices.Contains(u.Roles, s.cfg.AdminRole) && (u.HasPassword() || s.cfg.ExternalLogin)
}

// keepAnAdmin refuses when no other enabled administrator exists.
func (s *Service) keepAnAdmin(ctx context.Context, exceptID string) error {
	all, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}

	for _, other := range all {
		if other.ID != exceptID && s.activeAdmin(other) {
			return nil
		}
	}

	return ErrLastAdmin
}

func (s *Service) hash(pass string) (string, error) {
	if len([]rune(pass)) < s.cfg.MinPasswordLength {
		return "", fmt.Errorf("%w: password must be at least %d characters", ErrInvalid, s.cfg.MinPasswordLength)
	}
	if len(pass) > password.MaxLength {
		return "", fmt.Errorf("%w: password is too long", ErrInvalid)
	}

	h, err := s.cfg.Hasher.Hash(pass)
	if err != nil {
		return "", fmt.Errorf("users: hash password: %w", err)
	}

	return h, nil
}

func (s *Service) validUsername(raw string) (string, error) {
	name := strings.TrimSpace(raw)

	if l := len([]rune(name)); l < 2 || l > 64 {
		return "", fmt.Errorf("%w: username must be 2 to 64 characters", ErrInvalid)
	}

	for _, c := range name {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && !strings.ContainsRune("._-@+", c) {
			return "", fmt.Errorf("%w: username may contain letters, digits and . _ - @ +", ErrInvalid)
		}
	}

	return name, nil
}

func (s *Service) validRoles(roles []string) ([]string, error) {
	out := make([]string, 0, len(roles))

	for _, r := range roles {
		if _, ok := s.roles[r]; !ok {
			return nil, fmt.Errorf("%w: unknown role %q", ErrInvalid, r)
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}

	return out, nil
}

func validEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil
	}

	at := strings.LastIndexByte(email, '@')
	if at < 1 || at == len(email)-1 || strings.ContainsAny(email, " \t\r\n<>") || len(email) > 254 {
		return fmt.Errorf("%w: invalid email", ErrInvalid)
	}

	return nil
}

func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("users: random: %w", err))
	}

	return hex.EncodeToString(b)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}

	return ""
}
