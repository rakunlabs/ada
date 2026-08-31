# Performance

Ada is designed for low overhead with zero heap allocations on the request hot path. This page documents benchmark results comparing ada against [Echo](https://echo.labstack.com/) and [Gin](https://gin-gonic.com/).

## Methodology

All benchmarks use `httptest.NewRecorder` + `httptest.NewRequest` and call `ServeHTTP` directly — no TCP overhead, pure router + middleware performance. Each benchmark runs with `-benchmem -count=3` and reports the median result.

Environment: Go 1.26.2, Linux, AMD Ryzen 7 5800X, 16 logical CPUs. Framework versions: Echo v5.3.0 and Gin v1.12.0. Results will vary by hardware — run the benchmarks yourself for your specific environment.

Source code: [`_examples/benchmark/`](https://github.com/rakunlabs/ada/tree/main/_examples/benchmark)

## Router Benchmarks

### Comparison: Ada vs Echo vs Gin

| Benchmark | Ada | Echo | Gin |
|---|---|---|---|
| **Static routes (5)** | **98.8 ns, 0 alloc** | 201.7 ns, 0 alloc | 171.6 ns, 0 alloc |
| **Static deep** `/api/v1/users/list/all` | **26.2 ns, 0 alloc** | 49.7 ns, 0 alloc | 35.0 ns, 0 alloc |
| **1 param** `/users/{id}` | **39.7 ns, 0 alloc** | 43.8 ns, 0 alloc | 41.3 ns, 0 alloc |
| **3 params** `/api/{v}/users/{id}/posts/{pid}` | 100.9 ns, 0 alloc | 66.3 ns, 0 alloc | **54.0 ns, 0 alloc** |
| **5 middlewares** | **33.4 ns, 0 alloc** | 40.9 ns, 0 alloc | 50.8 ns, 0 alloc |

### Key Takeaways

**Routing**: Ada uses a full-path compressed radix trie — '/' separators live inside the radix keys, so one comparison can match several path segments at once, and the '/' bookkeeping metadata for each key is pre-computed at registration time. This makes ada the fastest of the three on static routes and single-param routes. Param-heavy paths (3+ params) remain slower than Echo/Gin because each param requires a segment-boundary stop and a stdlib-compatible `SetPathValue` map write per param — the price of keeping handlers as plain `http.HandlerFunc` with `r.PathValue` support.

**Middleware**: Ada's middleware chain is baked at registration time. All three frameworks complete the five-middleware benchmark without heap allocations. Ada is about **18% faster than Echo v5** and **34% faster than Gin** in this benchmark.

**Allocations**: All three frameworks achieve zero heap allocations for routing. Ada uses in-place path walking (no `strings.Split`) and a sorted children slice (no Go map hashing).

**In practice**: The routing differences (a few ns to roughly 47 ns in these scenarios) are negligible for real HTTP handlers that do 1-100 ms of actual work (database queries, API calls, JSON serialization). At 100k requests/second, the entire routing overhead is less than 1% of total CPU time. Router choice should therefore consider API design and operational features alongside these synthetic hot-path results.

## Ada-Only Detailed Benchmarks

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| Static root `/` | 12.44 | 0 | 0 |
| Static short `/users` | 18.90 | 0 | 0 |
| Static deep `/api/v1/users/list/all` | 19.25 | 0 | 0 |
| 1 param `/users/{id}` | 39.06 | 0 | 0 |
| 3 params | 97.29 | 0 | 0 |
| Wildcard `/files/*` | 43.07 | 0 | 0 |
| 50 mixed routes | 41.89 | 0 | 0 |
| 200 mixed routes | 46.80 | 0 | 0 |
| 404 Not Found | 218.1 | 98 | 3 |
| 405 Method Not Allowed | 265.6 | 123 | 4 |
| 0 middlewares | 18.81 | 0 | 0 |
| 1 middleware | 20.57 | 0 | 0 |
| 5 middlewares | 32.20 | 0 | 0 |
| 10 middlewares | 45.74 | 0 | 0 |
| Slot (runtime reload) | 25.96 | 0 | 0 |
| Pipeline (3 entries) | 30.26 | 0 | 0 |
| Pipeline (5 entries) | 35.40 | 0 | 0 |

### Notes

- **Middleware scaling**: 0 to 10 middlewares adds only ~27 ns because the chain is pre-built at registration time. The per-request cost is a function-call chain, not a loop.
- **Route count scaling**: 50 routes to 200 routes adds only ~5 ns due to the radix trie structure — lookup is O(path length), not O(route count).
- **Slot / Pipeline overhead**: ~3-5 ns over an equivalent static middleware. Both use pre-built handler chains with zero allocations. The only per-request cost is one atomic pointer load. When `WithTimeout` variants are active, one context derivation is added per request (~400 ns); this cost is only paid when timeout-based cancellation is in use.
- **404/405 allocations**: The remaining allocations on these paths come from stdlib `http.Error` / `http.NotFound` (header map write + body formatting). The middleware chain itself is pre-built at registration time and allocation-free per request.

## Optimizations

Ada's router achieves its performance through several key optimizations:

- **Full-path compressed radix trie**: '/' separators are part of the radix keys, so consecutive static segments compress into a single key and one `memequal` comparison can consume several segments. Param/wildcard alternatives anchor at segment-start nodes and are only consulted on static dead ends.
- **Sorted children slice**: Trie child lookups use a sorted `[]staticChild` slice with linear scan instead of a Go `map[byte]*node`. For the typical 1-4 children per node, linear scan on contiguous memory (~0.5 ns) is significantly faster than Go map hashing (~8 ns).
- **Inlined node structure**: Static trie fields (`StaticKey`, `StaticChildren`) are inlined directly in the `node` struct, eliminating a pointer dereference per trie level and improving cache locality.
- **Pre-computed key slash metadata**: The position of the last '/' and the '/' count of each radix key are computed once at registration time and stored on the node, so per-request segment bookkeeping avoids `strings.LastIndexByte` / `strings.Count` on every key hop.
- **In-place path walking**: Request paths are walked byte-wise without allocating a `[]string` slice. Wildcard values are reconstructed via substring of the original path.
- **Pre-chained error handlers**: The 404/405 middleware chains are composed at registration time, not per request. The `Allow` header for 405/auto-OPTIONS responses is pre-computed on each node at registration.
- **Pre-built middleware chains**: Middleware is composed into a single handler closure at route registration time. Per-request cost is zero — no chain resolution, no allocation, no loop.
- **Slice-based method dispatch**: Per-node method handlers live in a small `[]methodEntry` slice scanned linearly instead of a `map[string]http.HandlerFunc`. For the typical 1-4 methods per node, a string comparison beats map hashing. The entry also carries the route pattern and pre-computed param names, so dispatch resolves handler, pattern, and params in a single lookup with no wrapper closure.
- **Pre-built Slot/Pipeline chains**: Both Slot and Pipeline pre-build handler chains at mutation time (not per-request). The hot path is one atomic pointer load (~1 ns) with zero allocations. Cancel contexts for `WithTimeout` variants are opt-in — only created when timeout-based cancellation is actually used.
- **Leak-free context merging**: When `WithTimeout` is active, `mergeContexts` returns a cleanup function that deregisters watchers from the generation context, preventing unbounded memory growth across requests.
- **Direct method strings**: HTTP methods from `net/http` are already uppercase per RFC 7230, so no `strings.ToUpper` conversion is needed.

## Running Benchmarks

### Ada-only benchmarks

```sh
# From the repository root
go test -bench=. -benchmem -count=3 .
```

### Framework comparison

```sh
# From _examples/benchmark/
go test -bench=. -benchmem -count=3 .
```

### Comparison with benchstat

For statistically rigorous comparison:

```sh
cd _examples/benchmark
go test -bench=BenchmarkAda -benchmem -count=10 . > ada.txt
go test -bench=BenchmarkEcho -benchmem -count=10 . > echo.txt
go test -bench=BenchmarkGin -benchmem -count=10 . > gin.txt
# Use benchstat to compare (go install golang.org/x/perf/cmd/benchstat@latest)
```
