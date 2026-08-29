package ada

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func statusOf(t *testing.T, mux *Mux, method, path string) (int, string) {
	t.Helper()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))

	return rec.Code, rec.Body.String()
}

// TestRuntimeAddRoute pins that a route registered after the Mux has already
// served a request is picked up by the next one.
func TestRuntimeAddRoute(t *testing.T) {
	mux := NewMux()
	mux.GET("/first", func(c *Context) error { return c.SendString("first") })

	// Serve once so a snapshot has been published; the next registration
	// has to invalidate it.
	if code, _ := statusOf(t, mux, http.MethodGet, "/first"); code != http.StatusOK {
		t.Fatalf("warmup status = %d, want 200", code)
	}

	if code, _ := statusOf(t, mux, http.MethodGet, "/second"); code != http.StatusNotFound {
		t.Fatalf("status before adding = %d, want 404", code)
	}

	mux.GET("/second", func(c *Context) error { return c.SendString("second") })

	code, body := statusOf(t, mux, http.MethodGet, "/second")
	if code != http.StatusOK || body != "second" {
		t.Fatalf("status = %d body = %q, want 200 / %q", code, body, "second")
	}

	// The route that was already there must still work.
	if code, body := statusOf(t, mux, http.MethodGet, "/first"); code != http.StatusOK || body != "first" {
		t.Fatalf("pre-existing route broke: status = %d body = %q", code, body)
	}
}

// TestRuntimeRemoveRoute pins removal, including the 405/404 distinction: a
// path that still has another method registered must answer 405, and one left
// with nothing must answer 404.
func TestRuntimeRemoveRoute(t *testing.T) {
	mux := NewMux()
	mux.GET("/items", func(c *Context) error { return c.SendString("list") })
	mux.POST("/items", func(c *Context) error { return c.SendString("create") })
	mux.GET("/solo", func(c *Context) error { return c.SendString("solo") })

	if code, _ := statusOf(t, mux, http.MethodGet, "/items"); code != http.StatusOK {
		t.Fatalf("warmup status = %d, want 200", code)
	}

	if !mux.Remove(http.MethodGet, "/items") {
		t.Fatal("Remove reported nothing removed")
	}

	// POST survives, so GET is now Method Not Allowed rather than missing.
	if code, _ := statusOf(t, mux, http.MethodGet, "/items"); code != http.StatusMethodNotAllowed {
		t.Fatalf("removed method status = %d, want 405", code)
	}

	if code, body := statusOf(t, mux, http.MethodPost, "/items"); code != http.StatusOK || body != "create" {
		t.Fatalf("sibling method broke: status = %d body = %q", code, body)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/items", nil))

	if allow := rec.Header().Get("Allow"); allow != "OPTIONS, POST" {
		t.Fatalf("Allow = %q, want %q", allow, "OPTIONS, POST")
	}

	// Removing the last method leaves nothing to report, so it is a 404.
	if !mux.Remove(http.MethodGet, "/solo") {
		t.Fatal("Remove reported nothing removed for /solo")
	}

	if code, _ := statusOf(t, mux, http.MethodGet, "/solo"); code != http.StatusNotFound {
		t.Fatalf("emptied path status = %d, want 404", code)
	}

	if mux.Remove(http.MethodGet, "/solo") {
		t.Fatal("removing twice reported a removal the second time")
	}
}

// TestRuntimeRemoveThenReAdd pins that a removed pattern can be registered
// again — the emptied node left behind must not shadow the new handler.
func TestRuntimeRemoveThenReAdd(t *testing.T) {
	mux := NewMux()
	mux.GET("/toggle", func(c *Context) error { return c.SendString("v1") })

	if code, body := statusOf(t, mux, http.MethodGet, "/toggle"); code != http.StatusOK || body != "v1" {
		t.Fatalf("status = %d body = %q", code, body)
	}

	mux.Remove(http.MethodGet, "/toggle")

	if code, _ := statusOf(t, mux, http.MethodGet, "/toggle"); code != http.StatusNotFound {
		t.Fatalf("status after remove = %d, want 404", code)
	}

	mux.GET("/toggle", func(c *Context) error { return c.SendString("v2") })

	if code, body := statusOf(t, mux, http.MethodGet, "/toggle"); code != http.StatusOK || body != "v2" {
		t.Fatalf("status = %d body = %q, want 200 / v2", code, body)
	}
}

// TestRuntimeRemoveParamAndWildcard pins removal for the non-static route
// shapes, which live on separate edges of the trie.
func TestRuntimeRemoveParamAndWildcard(t *testing.T) {
	mux := NewMux()
	mux.GET("/users/{id}", func(c *Context) error { return c.SendString(c.Request.PathValue("id")) })
	mux.HandleFuncWildcard("/assets/", func(c *Context) error { return c.SendString("asset") })

	if code, body := statusOf(t, mux, http.MethodGet, "/users/7"); code != http.StatusOK || body != "7" {
		t.Fatalf("param route: status = %d body = %q", code, body)
	}

	if code, _ := statusOf(t, mux, http.MethodGet, "/assets/js/app.js"); code != http.StatusOK {
		t.Fatalf("wildcard route: status = %d, want 200", code)
	}

	if !mux.Remove(http.MethodGet, "/users/{id}") {
		t.Fatal("param route not removed")
	}

	if code, _ := statusOf(t, mux, http.MethodGet, "/users/7"); code != http.StatusNotFound {
		t.Fatalf("removed param route: status = %d, want 404", code)
	}

	// HandleFuncWildcard registers a catch-all, i.e. the empty method.
	if !mux.RemoveWildcard("/assets/") {
		t.Fatal("wildcard route not removed")
	}

	if code, _ := statusOf(t, mux, http.MethodGet, "/assets/js/app.js"); code != http.StatusNotFound {
		t.Fatalf("removed wildcard route: status = %d, want 404", code)
	}
}

// TestRuntimeGroupSharesRouteTable pins that a Group registers into — and
// removes from — the same table as its parent, with its prefix applied.
func TestRuntimeGroupSharesRouteTable(t *testing.T) {
	mux := NewMux()
	api := mux.Group("/api")

	api.GET("/users", func(c *Context) error { return c.SendString("users") })

	if code, body := statusOf(t, mux, http.MethodGet, "/api/users"); code != http.StatusOK || body != "users" {
		t.Fatalf("status = %d body = %q", code, body)
	}

	// The group's Remove must resolve against the group prefix.
	if !api.Remove(http.MethodGet, "/users") {
		t.Fatal("group Remove reported nothing removed")
	}

	if code, _ := statusOf(t, mux, http.MethodGet, "/api/users"); code != http.StatusNotFound {
		t.Fatalf("status after group remove = %d, want 404", code)
	}

	// Adding through the group afterwards must still reach the parent's table.
	api.GET("/health", func(c *Context) error { return c.SendString("ok") })

	if code, body := statusOf(t, mux, http.MethodGet, "/api/health"); code != http.StatusOK || body != "ok" {
		t.Fatalf("status = %d body = %q", code, body)
	}
}

// TestRoutesListing pins the introspection output, group prefixes included.
func TestRoutesListing(t *testing.T) {
	mux := NewMux()
	mux.GET("/health", func(c *Context) error { return nil })
	mux.POST("/items", func(c *Context) error { return nil })
	mux.Group("/api").GET("/users/{id}", func(c *Context) error { return nil })

	want := map[string]bool{
		"GET /health":         true,
		"POST /items":         true,
		"GET /api/users/{id}": true,
	}

	got := map[string]bool{}
	for _, route := range mux.Routes() {
		got[route.Method+" "+route.Pattern] = true
	}

	for key := range want {
		if !got[key] {
			t.Errorf("missing route %q in %v", key, got)
		}
	}

	mux.Remove(http.MethodPost, "/items")

	for _, route := range mux.Routes() {
		if route.Method == http.MethodPost && route.Pattern == "/items" {
			t.Fatal("removed route still listed")
		}
	}
}

// TestRuntimeReloadUnderLoad hammers the Mux with concurrent requests while
// routes are added and removed. Under -race this is what catches a request
// reading a tree a registration is mutating.
func TestRuntimeReloadUnderLoad(t *testing.T) {
	mux := NewMux()
	mux.GET("/stable", func(c *Context) error { return c.SendString("stable") })

	var (
		readersWG sync.WaitGroup
		writersWG sync.WaitGroup
		stop      atomic.Bool
	)
	start := make(chan struct{})

	const readers = 16

	readersWG.Add(readers)

	for range readers {
		go func() {
			defer readersWG.Done()
			<-start

			for !stop.Load() {
				// The stable route must never disappear, whatever the
				// writers are doing to the rest of the table.
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stable", nil))

				if rec.Code != http.StatusOK || rec.Body.String() != "stable" {
					t.Errorf("stable route: status = %d body = %q", rec.Code, rec.Body.String())

					return
				}

				// Churned routes may legitimately be present or absent;
				// only a torn read would show up, as a panic or a race.
				rec = httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/churn/7/detail", nil))
			}
		}()
	}

	writersWG.Add(2)

	for range 2 {
		go func() {
			defer writersWG.Done()
			<-start

			for range 300 {
				mux.GET("/churn/{id}/detail", func(c *Context) error { return c.SendString("churn") })
				mux.Remove(http.MethodGet, "/churn/{id}/detail")
			}
		}()
	}

	close(start)

	// Writers finish on their own; readers spin until told to stop, so the
	// order matters: signalling after waiting on the readers would deadlock.
	writersWG.Wait()
	stop.Store(true)
	readersWG.Wait()
}

// TestRouteTableStartupDoesNotClonePerRoute pins the lazy-publication
// property: registering many routes before the first request must publish
// exactly once, not once per route. Without it, startup is O(routes²).
func TestRouteTableStartupDoesNotClonePerRoute(t *testing.T) {
	mux := NewMux()

	for i := range 200 {
		mux.GET(fmt.Sprintf("/route/%d", i), func(c *Context) error { return nil })
	}

	// No request yet, so nothing should have been published.
	if mux.routes.root.Load() != nil {
		t.Fatal("a snapshot was published before the first request")
	}

	statusOf(t, mux, http.MethodGet, "/route/0")

	published := mux.routes.root.Load()
	if published == nil {
		t.Fatal("no snapshot published after the first request")
	}

	// A second request must reuse the same snapshot rather than rebuild.
	statusOf(t, mux, http.MethodGet, "/route/1")

	if mux.routes.root.Load() != published {
		t.Fatal("snapshot rebuilt for a request that changed nothing")
	}
}

// TestSnapshotIsolatesInFlightRequest pins that a handler which is already
// running keeps routing against the table its request started with: a removal
// landing mid-request must not change what that request already matched.
func TestSnapshotIsolatesInFlightRequest(t *testing.T) {
	mux := NewMux()

	entered := make(chan struct{})
	released := make(chan struct{})

	mux.GET("/slow", func(c *Context) error {
		close(entered)
		<-released

		return c.SendString("slow")
	})

	done := make(chan string, 1)

	go func() {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/slow", nil))
		done <- rec.Body.String()
	}()

	<-entered

	// Remove the route the in-flight request is inside of.
	if !mux.Remove(http.MethodGet, "/slow") {
		t.Fatal("Remove reported nothing removed")
	}

	close(released)

	if body := <-done; body != "slow" {
		t.Fatalf("in-flight request body = %q, want %q", body, "slow")
	}

	// New requests do see the removal.
	if code, _ := statusOf(t, mux, http.MethodGet, "/slow"); code != http.StatusNotFound {
		t.Fatalf("status after remove = %d, want 404", code)
	}
}

func TestMissingRemoveKeepsPublishedSnapshot(t *testing.T) {
	mux := NewMux()
	mux.GET("/stable", func(c *Context) error { return c.SendString("ok") })
	statusOf(t, mux, http.MethodGet, "/stable")

	published := mux.routes.root.Load()
	if mux.Remove(http.MethodGet, "/missing") {
		t.Fatal("missing route reported as removed")
	}
	if mux.routes.root.Load() != published {
		t.Fatal("missing Remove republished an unchanged route table")
	}
}

func TestRuntimeMutationPublishesBeforeReturning(t *testing.T) {
	mux := NewMux()
	mux.GET("/first", func(c *Context) error { return nil })
	statusOf(t, mux, http.MethodGet, "/first")

	old := mux.routes.root.Load()
	mux.GET("/second", func(c *Context) error { return nil })

	if next := mux.routes.root.Load(); next == nil || next == old {
		t.Fatal("runtime registration did not eagerly publish its snapshot")
	}
}

func TestApplyRoutesPublishesOneAtomicBatch(t *testing.T) {
	mux := NewMux()
	mux.GET("/old", func(c *Context) error { return c.SendString("old") })
	statusOf(t, mux, http.MethodGet, "/old")

	oldRoot := mux.routes.root.Load()
	mux.ApplyRoutes(func(b *RouteBuilder) {
		b.Remove(http.MethodGet, "/old")
		b.HandleWithMethod(http.MethodGet, "/a", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("a"))
		}))
		b.HandleWithMethod(http.MethodGet, "/b", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("b"))
		}))
	})

	newRoot := mux.routes.root.Load()
	if newRoot == nil || newRoot == oldRoot {
		t.Fatal("batch did not publish a new snapshot")
	}

	var oldResult matchResult
	mux.match(oldRoot, "/old", &oldResult)
	if oldResult.node == nil || oldResult.node.lookupEntry(http.MethodGet) == nil {
		t.Fatal("old snapshot was mutated by ApplyRoutes")
	}

	if code, _ := statusOf(t, mux, http.MethodGet, "/old"); code != http.StatusNotFound {
		t.Fatalf("old route status = %d, want 404", code)
	}
	for _, routePath := range []string{"/a", "/b"} {
		if code, body := statusOf(t, mux, http.MethodGet, routePath); code != http.StatusOK || body != routePath[1:] {
			t.Fatalf("%s: status = %d body = %q", routePath, code, body)
		}
	}
}

func TestApplyRoutesRollsBackPanic(t *testing.T) {
	mux := NewMux()
	mux.GET("/stable", func(c *Context) error { return c.SendString("stable") })
	statusOf(t, mux, http.MethodGet, "/stable")
	published := mux.routes.root.Load()

	func() {
		defer func() { _ = recover() }()
		mux.ApplyRoutes(func(b *RouteBuilder) {
			b.Remove(http.MethodGet, "/stable")
			panic("abort")
		})
	}()

	if mux.routes.root.Load() != published {
		t.Fatal("panicked batch changed the published snapshot")
	}
	if code, body := statusOf(t, mux, http.MethodGet, "/stable"); code != http.StatusOK || body != "stable" {
		t.Fatalf("stable route changed after rollback: status = %d body = %q", code, body)
	}
}
