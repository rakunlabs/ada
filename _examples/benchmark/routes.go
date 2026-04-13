// Package benchmark provides common route definitions for comparing
// ada, echo, and gin routers with identical workloads.
package benchmark

// Routes defines the common route patterns used across all framework benchmarks.
var StaticRoutes = []struct {
	Method string
	Path   string
}{
	{"GET", "/"},
	{"GET", "/users"},
	{"GET", "/api/v1/users/list/all"},
	{"POST", "/api/v1/users"},
	{"GET", "/health"},
}

var ParamRoutes = []struct {
	Method  string
	Pattern string
	Request string
}{
	{"GET", "/users/:id", "/users/12345"},
	{"GET", "/api/:version/users/:userId/posts/:postId", "/api/v2/users/42/posts/789"},
	{"PUT", "/users/:id/settings", "/users/99/settings"},
}

// AdaParamRoutes uses {param} syntax for ada.
var AdaParamRoutes = []struct {
	Method  string
	Pattern string
	Request string
}{
	{"GET", "/users/{id}", "/users/12345"},
	{"GET", "/api/{version}/users/{userId}/posts/{postId}", "/api/v2/users/42/posts/789"},
	{"PUT", "/users/{id}/settings", "/users/99/settings"},
}
