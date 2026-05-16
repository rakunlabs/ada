# Performance

Ada is designed for low overhead with zero heap allocations on the request hot path. This page documents benchmark results comparing ada against [Echo](https://echo.labstack.com/) and [Gin](https://gin-gonic.com/).

## Methodology

All benchmarks use `httptest.NewRecorder` + `httptest.NewRequest` and call `ServeHTTP` directly — no TCP overhead, pure router + middleware performance. Each benchmark runs with `-benchmem -count=3` and reports the median result.

Environment: Go 1.24, Linux, 16 cores. Results will vary by hardware — run the benchmarks yourself for your specific environment.

Source code: [`_examples/benchmark/`](https://github.com/rakunlabs/ada/tree/main/_examples/benchmark)

## Router Benchmarks

### Comparison: Ada vs Echo vs Gin

| Benchmark | Ada | Echo | Gin |
|---|---|---|---|
| **Static routes (5)** | 199 ns, 0 alloc | 164 ns, 0 alloc | 165 ns, 0 alloc |
| **Static deep** `/api/v1/users/list/all` | 69 ns, 0 alloc | 43 ns, 0 alloc | 34 ns, 0 alloc |
| **1 param** `/users/{id}` | 57 ns, 0 alloc | 43 ns, 0 alloc | 39 ns, 0 alloc |
| **3 params** `/api/{v}/users/{id}/posts/{pid}` | 129 ns, 0 alloc | 66 ns, 0 alloc | 53 ns, 0 alloc |
| **5 middlewares** | **42 ns, 0 alloc** | 122 ns, 5 allocs | 49 ns, 0 alloc |

### Key Takeaways

**Routing**: Ada's router is within 1.5-2x of Echo and Gin for path lookup. Gin and Echo still have a raw-speed advantage due to their compressed radix trie implementations that can match multi-segment prefixes in a single comparison. Ada walks per-segment but uses a sorted-slice children structure that keeps lookup fast with zero map overhead.

**Middleware**: Ada's middleware chain is baked at registration time with zero per-request overhead. Echo allocates per middleware per request (5 allocs for 5 middlewares). Ada is **3x faster than Echo** on middleware and slightly faster than Gin. This is ada's strongest performance advantage.

**Allocations**: All three frameworks achieve zero heap allocations for routing. Ada uses in-place path walking (no `strings.Split`) and a sorted children slice (no Go map hashing).

**In practice**: The routing difference (15-60 ns) is negligible for real HTTP handlers that do 1-100 ms of actual work (database queries, API calls, JSON serialization). At 100k requests/second, the entire routing overhead is less than 1% of total CPU time. The middleware allocation difference matters more for high-throughput services — Echo's 5 allocs/request at 100k RPS means 500k unnecessary allocations per second and additional GC pressure.

## Ada-Only Detailed Benchmarks

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| Static root `/` | 23 | 0 | 0 |
| Static short `/users` | 28 | 0 | 0 |
| Static deep `/api/v1/users/list/all` | 69 | 0 | 0 |
| 1 param `/users/{id}` | 57 | 0 | 0 |
| 3 params | 128 | 0 | 0 |
| Wildcard `/files/*` | 63 | 0 | 0 |
| 50 mixed routes | 59 | 0 | 0 |
| 200 mixed routes | 61 | 0 | 0 |
| 404 Not Found | 250 | 104 | 3 |
| 405 Method Not Allowed | 591 | 219 | 6 |
| 0 middlewares | 28 | 0 | 0 |
| 1 middleware | 30 | 0 | 0 |
| 5 middlewares | 43 | 0 | 0 |
| 10 middlewares | 56 | 0 | 0 |
| Slot (runtime reload) | 35 | 0 | 0 |
| Pipeline (3 entries) | 40 | 0 | 0 |
| Pipeline (5 entries) | 48 | 0 | 0 |

### Notes

- **Middleware scaling**: 0 to 10 middlewares adds only ~28 ns because the chain is pre-built at registration time. The per-request cost is a function-call chain, not a loop.
- **Route count scaling**: 50 routes to 200 routes adds only ~2 ns due to the radix trie structure — lookup is O(path length), not O(route count).
- **Slot / Pipeline overhead**: ~5-8 ns over an equivalent static middleware. Both use pre-built handler chains with zero allocations. The only per-request cost is two atomic pointer loads. When `WithTimeout` variants are active, one context derivation is added per request (~400 ns); this cost is only paid when timeout-based cancellation is in use.
- **404/405 allocations**: These paths go through `http.Error` and `Chain(middlewares...)` which allocate. This is acceptable since error paths are not performance-critical.

## Optimizations

Ada's router achieves its performance through several key optimizations:

- **Sorted children slice**: Trie child lookups use a sorted `[]staticChild` slice with linear scan instead of a Go `map[byte]*node`. For the typical 1-4 children per node, linear scan on contiguous memory (~0.5 ns) is significantly faster than Go map hashing (~8 ns).
- **Inlined node structure**: Static trie fields (`StaticKey`, `StaticChildren`) are inlined directly in the `node` struct, eliminating a pointer dereference per trie level and improving cache locality.
- **In-place path walking**: Request paths are walked using `strings.IndexByte` without allocating a `[]string` slice. Wildcard values are reconstructed via substring of the original path.
- **Pre-built middleware chains**: Middleware is composed into a single handler closure at route registration time. Per-request cost is zero — no chain resolution, no allocation, no loop.
- **Pre-built Slot/Pipeline chains**: Both Slot and Pipeline pre-build handler chains at mutation time (not per-request). The hot path is two atomic pointer loads (~2 ns) with zero allocations. Cancel contexts for `WithTimeout` variants are opt-in — only created when timeout-based cancellation is actually used.
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
