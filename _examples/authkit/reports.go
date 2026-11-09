package authkit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
)

// Report is the example's domain object. Kept in memory: the point of the
// example is the auth around it.
type Report struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
}

type reports struct {
	mu    sync.Mutex
	items []Report
}

func newReports() *reports {
	return &reports{items: []Report{
		{ID: "r1", Title: "Q3 revenue", Author: "system", CreatedAt: time.Now()},
		{ID: "r2", Title: "Churn by cohort", Author: "system", CreatedAt: time.Now()},
	}}
}

type reportsApp struct{ reports *reports }

func (a *reportsApp) list(c *ada.Context) error {
	a.reports.mu.Lock()
	defer a.reports.mu.Unlock()

	return c.SendJSON(a.reports.items)
}

func (a *reportsApp) create(c *ada.Context) error {
	var in struct {
		Title string `json:"title"`
	}
	if err := c.Bind(&in); err != nil || in.Title == "" {
		return ada.NewHTTPError(http.StatusBadRequest, "title is required")
	}

	id := identity.FromContext(c.Request.Context())

	b := make([]byte, 4)
	_, _ = rand.Read(b)

	r := Report{ID: hex.EncodeToString(b), Title: in.Title, Author: id.Name, CreatedAt: time.Now()}

	a.reports.mu.Lock()
	a.reports.items = append(a.reports.items, r)
	a.reports.mu.Unlock()

	return c.SetStatus(http.StatusCreated).SendJSON(r)
}

func (a *reportsApp) remove(c *ada.Context) error {
	a.reports.mu.Lock()
	defer a.reports.mu.Unlock()

	n := len(a.reports.items)
	a.reports.items = slices.DeleteFunc(a.reports.items, func(r Report) bool { return r.ID == c.Request.PathValue("id") })

	if len(a.reports.items) == n {
		return ada.NewHTTPError(http.StatusNotFound, "no such report")
	}

	return c.SendNoContent()
}

// mcp stands in for an MCP server: it answers who is calling and how. Put a
// real one (github.com/modelcontextprotocol/go-sdk) behind the same guards.
func (a *reportsApp) mcp(w http.ResponseWriter, r *http.Request) {
	id := identity.FromContext(r.Context())

	out := map[string]any{
		"subject": id.Subject,
		"name":    id.Name,
		"roles":   id.Roles,
		"scopes":  id.Scopes,
		"via":     id.Provider,
	}

	if info := oauthserver.Info(id); info != nil {
		out["token_id"] = info.ID
		out["client_id"] = info.ClientID
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
