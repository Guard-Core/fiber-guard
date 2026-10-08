# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

fiber-guard is a Fiber middleware adapter for [guard-core-go](https://github.com/Guard-Core/guard-core-go). It translates `fiber.Ctx` into the guardcore request surface, runs the engine, and translates verdicts to exact Fiber responses. It contains NO security logic of its own.

- Module: `github.com/rennf93/fiber-guard`, Go directive `go 1.25.0`, MIT license.
- Single Go package `fiber` at the repo root. Source files: `middleware.go`, `request.go`. Tests: `middleware_test.go`, `integration_test.go`. There are no subpackage directories.
- Release state: no tags exist yet. The repo ships untagged; depend on it via a commit reference until the first tag is cut. State this honestly; there is no changelog beyond git history.
- The public surface is small and deliberate: `New`, `Option`, `WithMaxBodyBytes`, `WithLogger`, `WithRouteID`, and the `DefaultMaxBodyBytes` constant (262144).

## Ecosystem Position

This repo is the ADAPTER layer of the guard-core ecosystem:

- `guard-core-go` is the engine. All detection (suspicious activity, IP bans, rate limits, HTTPS enforcement), verdict construction, and error response factories live there.
- This repo wires Go Fiber types to that engine and nothing more. It consumes `github.com/rennf93/guard-core-go/v4 v4.0.5-0.20260926230539-e39ac203568b` as a normal module dependency (see `go.mod`); no `replace` directive is used or needed. For cross-repo work on the core, add a temporary local `replace` in your own checkout and drop it before committing.
- Because the middleware is a `fiber.Handler`, it composes with `app.Use` and runs anywhere in a Fiber handler chain.
- Direct dependencies: `github.com/gofiber/fiber/v3 v3.5.0` (the framework this adapter exists for; a framework import is allowed here, unlike in the core), `github.com/valyala/fasthttp v1.73.0` (Fiber's own engine; the shim uses fasthttp primitives directly where Fiber's accessors are config-dependent, see Boundary Rules), and `github.com/rennf93/guard-core-go/v4 v4.0.5-0.20260926230539-e39ac203568b`. Notable indirect floors: `golang.org/x/crypto v0.55.0` (explicitly bumped for GO-2026-6303; fiber v3.5.0 pulled v0.54.0, and the SSH DoS fixes in v0.56.0 require a go 1.26 directive, so v0.55.0 is the highest floor compatible with `go 1.25.0`), plus the core's transitives (`redis/go-redis/v9 v9.22.0`, `dlclark/regexp2 v1.12.0`, `go.uber.org/atomic`, `golang.org/x/text v0.41.0`).

## Boundary Rules

- This adapter MUST NOT implement detection rules, rate limiting, ban storage, IP parsing heuristics, or any verdict logic. Every verdict comes from `engine.Check(req)` in `middleware.go`.
- This adapter MUST NOT reimplement client-IP trust policy. Client identity comes from the fasthttp TCP peer via `c.RequestCtx().RemoteIP().String()` in `ClientHost`. Fiber's `c.IP()` is intentionally not used: with `TrustProxy` plus a `ProxyHeader` configured it resolves the client from proxy headers, and trusting proxy headers is policy. The adapter passes the connection peer to the core exactly like the net/http and Gin sibling adapters pass `RemoteAddr`. Apps that want proxy-header trust should resolve it in their own outer middleware and feed the core through its own configuration surface, not by "fixing" this adapter.
- Scheme detection MUST stay config-independent too. `URLScheme` reads `c.RequestCtx().IsTLS()` (the analog of the gin shim's `req.TLS != nil`), not Fiber's `c.Scheme()`, which consults `X-Forwarded-Proto` once `TrustProxy` is enabled.
- Verdict translation MUST be exact. `applyResponse` in `middleware.go` sets each verdict header with `c.Set`, writes the verdict status code with `c.Status`, writes the body verbatim with `c.Write`, and returns without calling `c.Next()` (aborting in Fiber means not calling `c.Next()`). On a clean pass the adapter adds no headers and calls `c.Next()`. Note: fasthttp itself always surfaces a default `Content-Type: text/plain; charset=utf-8` on responses with bodies (and on the response from the start of the chain); that is server behavior, not adapter translation.
- The adapter MUST fail closed. If `engine.Check` returns an error or panics, the middleware logs via its logger and responds with `engine.CreateErrorResponse(500, "Security check failed")`. The handler is not called. A custom 500 body comes from `cfg.CustomErrorResponses[500]`, not from adapter code.
- The adapter MUST bound what the engine reads from the body. `request.go` caches at most `maxBytes` (default `DefaultMaxBodyBytes` = 262144) via `ReadBodyPrefix`. `Body()` and `ReadBodyPrefix` never return more than that prefix. Payload bytes beyond the bound are not scanned. Unlike the net/http and Gin siblings there is no `replayBody` wrapper: fasthttp buffers the request body in memory before the middleware runs, so the handler keeps reading the full body through Fiber (`c.Body()`) and the shim never consumes or replaces it. Honest corollary: the cap bounds scanning, not buffering. Network-level bounding is Fiber's `BodyLimit` config (default 4 MiB); document that pairing, do not try to re-derive it here. `Body()` also returns the Content-Encoding-decoded view (that is what Fiber handlers see), so that is what the engine scans; `BodyRaw` is available on the ctx if a future core need ever wants raw bytes.
- Route identity comes only from the Fiber user context. `WithRouteID(ctx, id)` wraps a `context.Context` under a private key; `newRequestShim` copies it out of `c.Context()` (Fiber's user-set context, non-nil by contract) into `guardcore.RequestState.GuardRouteID`. In Fiber, attach it with `c.SetContext(guardfiber.WithRouteID(c.Context(), "open"))` in a middleware registered before the guard. Route configuration itself (`engine.Routes.Register`, bypassed checks) lives in the core, not here.
- Header normalization (first value wins in received order, explicit `Host` availability, uppercased method defaulting to GET when empty) is adaptation, not policy. fasthttp, unlike net/http, includes `Host` (plus `Content-Length`/`Content-Type` when present) in its header iteration, so those reach the core; the shim iterates `Header.All()` in received order and keeps the first value per name. Fiber's own `c.Queries()` is last-value-wins per its docs, so the shim walks `QueryArgs().VisitAll` itself to give the core first-value-wins parity with the siblings.
- Verdict, scanning, and client-identity behavior must stay aligned with the nethttp-guard and gin-guard siblings; if the core contract changes, change all adapters together.

## Quick Start

```sh
git clone https://github.com/Guard-Core/fiber-guard
cd fiber-guard
go build ./...
go test ./...
```

Redis is only needed for integration tests. To run the full suite including them:

```sh
REDIS_HOST=127.0.0.1 go test -tags integration ./...
```

Minimal usage (from README.md):

```go
import (
    fiberlib "github.com/gofiber/fiber/v3"
    guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
    guardfiber "github.com/rennf93/fiber-guard"
)

cfg := guardcore.DefaultSecurityConfig()
engine, err := guardcore.NewEngine(cfg)
if err != nil { log.Fatal(err) }
if err := engine.Initialize(); err != nil { log.Fatal(err) }

guard, err := guardfiber.New(engine)
if err != nil { log.Fatal(err) }

app := fiberlib.New()
app.Use(guard)
app.Get("/api", func(c fiberlib.Ctx) error { return c.SendString("ok") })
log.Fatal(app.Listen(":8080"))
```

Note the import alias: the module path ends in `fiber-guard` but the package name is `fiber`, which collides with `github.com/gofiber/fiber/v3` (also package `fiber`), so an explicit alias such as `guardfiber "github.com/rennf93/fiber-guard"` is the idiomatic import.

## Development Commands

There is no Makefile. Every command below comes from the CI workflows or the README.

| Command | Purpose | Verified in |
| --- | --- | --- |
| `go build ./...` | Compile the single root package | standard go command for this layout |
| `gofmt -l .` | List unformatted files; CI fails if any are listed | `.github/workflows/ci.yml` step "gofmt check" |
| `gofmt -w .` | Rewrite files that gofmt would list | standard gofmt fix for the check above |
| `go vet ./...` | Static analysis | `.github/workflows/ci.yml`, `scheduled-lint.yml` |
| `go test ./...` | Unit tests (no Redis needed; `middleware_test.go` disables Redis) | `.github/workflows/ci.yml` step "go test (unit)" |
| `REDIS_HOST=127.0.0.1 go test -tags integration ./...` | Unit plus Redis-backed integration tests | `.github/workflows/ci.yml` step "go test (integration, redis)", README.md |
| `go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...` | Vulnerability scan | `.github/workflows/ci.yml` and `scheduled-lint.yml` |
| `docker compose -f examples/simple_app/docker-compose.yml up --build -d --wait` | Local live smoke of the guarded example app (assertions in `.github/workflows/live-smoke.yml`) | `.github/workflows/live-smoke.yml` |
| `pip install mkdocs-material && mkdocs build --strict` | Build the documentation site (CI deploys it on master) | `.github/workflows/docs.yml` |

CI runs the test job on a Go matrix of `1.25.x` and `1.26.x` (fail-fast disabled) with `GOTOOLCHAIN: auto`, plus a separate `govulncheck` job on stable Go. The integration step runs against a `redis:7-alpine` service container on port 6379 with `REDIS_HOST=127.0.0.1`.

## Project Structure

```
.
├── middleware.go        # New, Option, WithMaxBodyBytes, WithLogger, verdict application, fail-closed path
├── request.go           # requestShim (implements guardcore.Request), WithRouteID, DefaultMaxBodyBytes
├── middleware_test.go   # unit tests, real fiber app, Redis disabled
├── integration_test.go  # //go:build integration, Redis-backed, skips when REDIS_HOST is unset
├── go.mod / go.sum      # module github.com/rennf93/fiber-guard, requires fiber/v3 v3.5.0 and guard-core-go/v4 v4.0.5-0.20260926230539-e39ac203568b
├── README.md            # usage, options, fasthttp semantics, integration test instructions
├── LICENSE              # MIT
├── examples/            # example apps inside the root module (see examples/*/README.md)
│   ├── simple_app/      # minimal guarded fiber server: main.go, Dockerfile, docker-compose.yml (app + redis)
│   └── advanced_app/    # production-style: cmd/server, internal/config, internal/routes, Dockerfile, docker-compose.yml
├── mkdocs.yml           # mkdocs-material site definition (docs/ sources)
├── docs/                # documentation site sources: index.md, usage.md, configuration.md
└── .github/
    ├── workflows/ci.yml           # push/PR: gofmt, vet, unit, integration, govulncheck
    ├── workflows/release.yml      # tag push gate: same tests, plus module tag consumable check
    ├── workflows/scheduled-lint.yml  # weekly cron vet + govulncheck
    ├── workflows/code-ql.yml      # CodeQL go analysis on push/PR/weekly
    ├── workflows/live-smoke.yml   # dockerized smoke of both example apps (push/PR to master)
    ├── workflows/docs.yml         # mkdocs material site build (strict) + GitHub Pages deploy on master
    ├── workflows/container-release.yml  # publish the advanced example image to GHCR (release / examples change)
    ├── workflows/upstream-drift.yml     # daily adapter suite against guard-core-go@master
    ├── workflows/issue-link.yml   # PR must close an open issue (or carry no-issue)
    ├── workflows/summary.yml      # on-demand AI issue summaries via the needs-summary label
    ├── workflows/sync-labels.yml  # applies .github/labels.yml on change
    ├── workflows/greetings.yml    # first-time contributor welcome messages
    ├── workflows/labeler.yml      # labels PRs by changed files (.github/labeler.yml)
    ├── workflows/stale.yml        # daily stale sweep for issues and PRs
    ├── labeler.yml                # labeler path rules
    ├── labels.yml                 # label inventory applied by sync-labels
    └── dependabot.yml             # weekly gomod and github-actions updates
```

## Technology Stack

- Go, directive `go 1.25.0`; CI matrix tests 1.25.x and 1.26.x.
- `github.com/rennf93/guard-core-go/v4 v4.0.5-0.20260926230539-e39ac203568b` (direct require in `go.mod`), providing `guardcore.Engine`, `guardcore.Request`, `guardcore.Response`, `guardcore.SecurityConfig`.
- `github.com/gofiber/fiber/v3 v3.5.0` (direct require in `go.mod`), providing `fiber.Handler`, `fiber.Ctx`, and `fiber.App` for the bridging surface.
- `github.com/valyala/fasthttp v1.73.0` (direct require in `go.mod`): Fiber's underlying engine. Its types already appear in Fiber's public API (`Ctx.RequestCtx()` returns `*fasthttp.RequestCtx`); the shim imports it for the deterministic primitives (`RemoteIP`, `IsTLS`, `Request.Header.All()`, `QueryArgs().VisitAll()`).
- Redis 7 for integration tests (CI service container `redis:7-alpine`); runtime Redis usage is a guard-core-go concern, not this adapter's.
- GitHub Actions: CI on push and pull_request, Release Gate on `v*` tag push, weekly Scheduled Lint, CodeQL (go), dockerized Live Smoke of the example apps on push/PR to master, Docs Update (mkdocs strict build + Pages deploy), Container Release (advanced example image to GHCR), daily Upstream Drift against guard-core-go@master, issue-link, greetings, labeler, stale, summary, and label sync; Dependabot for gomod and actions. All workflows use minimal permissions and pinned action SHAs.

## Testing Guidelines

- Unit tests live in `middleware_test.go` and run with plain `go test ./...`. The helper `newTestEngine` builds a config with `EnableRedis = false` so no Redis is required.
- Tests drive a real `fiber.App`: `app.Handler()` yields the fasthttp request handler, which the `runFiberApp` helper invokes on a `fasthttp.RequestCtx` initialized with `fctx.Init(req, tcpAddr(remoteAddr), nil)`. This mirrors the gin suite's ability to choose the client IP per request (something `app.Test` cannot do, since its test connection has a fixed placeholder remote address). The wildcard probe route records whether it was reached, the response headers it saw, and the method, path, query, and body it received. `withCtx` runs a callback inside a live handler for direct `requestShim` tests.
- Requests are built with the fasthttp API (`newReq`, `req.Header.Add`, `req.Header.SetHost`); fasthttp canonicalizes methods on the wire and preserves duplicate header occurrences in received order through `Header.All()`, which is what the first-value-wins assertions pin.
- Integration tests in `integration_test.go` carry the `//go:build integration` build tag. They skip (not fail) when `REDIS_HOST` is unset. They use `cfg.RedisURL = "redis://" + host + ":6379"`, `cfg.RedisPrefix = "guard_core_fiber_test:"`, `cfg.RedisFailOpen = false`, and clean up the `banned_ips:*` and `rate_limit:rate:*` key patterns in `t.Cleanup` before closing the engine.
- Invariants the tests enforce; keep them true when changing code:
  - A blocked request must never reach the handler; a clean pass must reach it with the original method, path, and query, and no adapter-added headers (fasthttp's own default `Content-Type` is the one allowed exception).
  - Verdicts translate exactly: status, body (including `guardcore.IPBanBlockedMessage` and custom messages), and headers such as the 301 `Location` come from the verdict.
  - `Body()` is idempotent for the engine, the bounded prefix is the only part scanned, and the handler still reads the full body through Fiber afterwards.
  - Engine malfunction and panics inside `CustomRequestCheck` fail closed with a 500 and the fail-closed message.
- `TestRequestShimFiberContextConversion` pins the bridging contract itself: path, scheme, full URL, scheme replacement, uppercased method, fasthttp peer-IP extraction, first-value header normalization including `Host`, first-value query params, and `WithRouteID` context propagation. `TestRequestShimIPv6PeerIP` pins IPv6 peer identity.
- Match the existing style: table-free plain tests, `t.Helper()` helpers, `t.Fatalf` with got/want context.

## Code Quality Standards

- `gofmt -l .` must produce no output and `go vet ./...` must pass; CI rejects otherwise.
- `govulncheck ./...` must report zero vulnerabilities reachable from this module's code (CI job plus weekly scheduled run). If a bump of a fiber transitive is needed, record it as an explicit indirect floor in `go.mod` with the GO id in the commit message, and keep the `go` directive at 1.25.0 (a higher directive breaks the CI matrix's 1.25.x leg; pick the highest fixed version whose own `go` requirement is at most 1.25).
- Commits use conventional commits with scopes seen in ecosystem history: `feat(fiber):`, `test(fiber):`, `fix(deps):`, `ci:`, `chore:`, `docs:`.
- Keep the public API frozen unless a change is deliberate: two files, one package, six exported identifiers. Prefer table-free helper-based tests like the existing ones.
- Error handling convention: construction returns errors (`New` rejects a nil engine); request-time failures fail closed, never panic upward.

## Best Practices

- Never push to `main` and never push tags from routine work. A `v*` tag push triggers the Release Gate workflow, which re-runs the full matrix and verifies the module tag resolves from a clean consumer module.
- Work on a branch, open a PR against `main`, and keep the diff scoped. Do not merge your own PR without review.
- Do not add a `replace` directive for guard-core-go in a commit; it is consumed as a normal module dependency.
- Do not commit generated files, `.DS_Store`, or stray artifacts. Stage explicit paths only.
- When touching `request.go`, preserve the bounded-prefix cache invariants: prefix reads extend contiguously, `Body()` returns the bounded cache, values beyond the bound are clamped, and the shim never replaces or consumes the fiber request body.
- When touching `middleware.go`, preserve exact verdict translation, returning without `c.Next()` on a verdict, and the fail-closed 500 path.
- Do not vendor dependencies; `.gitignore` excludes `vendor/`.

## Related Projects

- [guard-core-go](https://github.com/Guard-Core/guard-core-go): the engine this adapter wraps. All security logic, configuration, verdicts, and Redis integration live there. Import it as `guardcore "github.com/rennf93/guard-core-go/v4/guardcore"`.
- [nethttp-guard](https://github.com/Guard-Core/nethttp-guard): the net/http sibling adapter with the same surface and behavior contract.
- [gin-guard](https://github.com/Guard-Core/gin-guard): the Gin sibling adapter; keep the three adapters behaviorally aligned.
