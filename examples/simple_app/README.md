# fiber-guard simple app

A minimal guarded Fiber server in a single `main.go`, wired to the
[guard-core-go](https://github.com/Guard-Core/guard-core-go) engine through the
[fiber-guard](https://github.com/Guard-Core/fiber-guard) adapter middleware. It
shows the canonical wiring and what the adapter does for you: request
translation, bounded body scanning, exact verdict translation (status,
headers, body, then the chain stops), and fail-closed 500s on engine
malfunction.

For a production-style layout (route registry, admin routes, graceful
shutdown), see [`../advanced_app`](../advanced_app).

## Run it

With Docker Compose (recommended, includes Redis):

```bash
cd examples/simple_app
docker compose up --build
```

Or with the Go toolchain (in-process state, no Redis needed):

```bash
go run ./examples/simple_app
```

## Endpoints

| Endpoint | What it demonstrates |
|---|---|
| `GET /` | API info; passes the guard |
| `GET /health` | Liveness probe; excluded from the pipeline via `ExcludePaths` |
| `POST /echo` | Body-bearing request; the handler reads the full body through Fiber after the engine scans its bounded prefix |
| `GET /rate/strict` | Per-endpoint rate limit: 1 request per 10 seconds (`EndpointRateLimits`) |
| `GET /search?q=...` | Query parameter scanning; XSS payloads trip the demo `xss` threat ban (threshold 1) and the verdict carries the custom 403 body |

## Try the security behavior

```bash
# Allowed
curl -i http://localhost:8080/

# Rate limited: the second request within 10 seconds returns 429
curl -i http://localhost:8080/rate/strict
curl -i http://localhost:8080/rate/strict

# Blocked: the XSS payload trips the xss threat ban (demo threshold 1) and
# the verdict carries the custom 403 body
curl -i -G http://localhost:8080/search --data-urlencode 'q=<script>alert(1)</script>'

# The client IP is now banned: every request returns the custom 403 body
curl -i http://localhost:8080/
```

## A note on address headers

The Python engine skips ssrf scanning for address headers (`host`,
`x-forwarded-for`, `x-real-ip`, ...) automatically. This Go port does not
apply that built-in exclusion yet, and the Fiber adapter forwards fasthttp's
explicit `Host` header, so `main.go` mirrors the exclusion through
`ExcludedDetectionHeaders`; without it, a plain `Host: localhost` request is
flagged as an ssrf attempt.

## Configuration knobs demonstrated

Inline comments in `main.go` walk through every knob used:

- Global rate limiting (`RateLimit`, `RateLimitWindow`) and per-endpoint
  overrides (`EndpointRateLimits`)
- Auto-banning (`AutoBanThreshold`, `AutoBanDuration`) plus a per-threat ban
  (`ThreatBanConfig` for `xss`)
- Penetration detection with all categories enabled
- Blocked user agents (regex patterns)
- `CustomErrorResponses` for consistent block bodies
- `ExcludePaths` for health and docs routes
- Redis via `REDIS_URL` / `REDIS_PREFIX` (compose wires Redis in; without it
  the managers fall back to in-process state)
- The `OnBlock` hook: the telemetry seam for wiring
  [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) (comment-level
  guidance in `main.go`; agent integration is not implemented in the engine
  port yet, and `EnableAgent` fails config validation)

## Fiber notes

- Import the adapter with an explicit alias: the package name is `fiber`,
  which collides with `github.com/gofiber/fiber/v3` (also package `fiber`);
  `guardfiber` is the idiomatic alias.
- `guardfiber.New(engine)` returns a `fiber.Handler`, so it composes with
  `app.Use` and can sit anywhere in a chain. Keep it as early as possible so
  blocked requests never reach your other middleware;
  `middleware/recover` stays outermost so handler panics are contained.
  Fiber has no explicit abort call: the guard writes the verdict to the
  response and the chain stops because it returns without calling
  `c.Next()`.
- `guardfiber.WithMaxBodyBytes` bounds the body bytes the engine scans
  (default 262144); bytes beyond the bound are not scanned, and the full
  body still reaches your handler through Fiber (`c.Body()`). Unlike the
  net/http and Gin siblings there is no replay wrapper: fasthttp buffers the
  request body in memory before the middleware runs, so the shim never
  consumes or replaces it (see the advanced example's fasthttp-vs-net/http
  notes for the details).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `REDIS_URL` | (unset; Redis disabled) | When set, bans and rate limits are shared through Redis |
| `REDIS_PREFIX` | `guard_core:` | Redis key prefix |

## Module layout note

Both example apps live inside the root module
(`github.com/rennf93/fiber-guard/examples/...`) rather than in separate Go
modules or a `go.work` workspace. Rationale: the examples pin the exact
adapter they document (same module, same commit), so `go vet ./...` and
`go build ./...` gate them together with the adapter in CI and the
Dockerfiles `COPY go.mod go.sum` only once. Splitting them out would let an
example drift against a published adapter version while still compiling. The
tradeoff: the examples' imports resolve only inside this module, which is
fine for copy-paste-driven reference code.
