# fiber-guard advanced example

A production-style Fiber service guarded by the
[fiber-guard](https://github.com/Guard-Core/fiber-guard) adapter over the
[guard-core-go](https://github.com/Guard-Core/guard-core-go) engine: multi-stage
Docker build, non-root runtime, Redis for shared bans and rate limits, the
engine's route registry for per-route config, fiber route groups, and admin
routes that drive the ban manager.

For the minimal single-file version, see [`../simple_app`](../simple_app).

## Architecture

```text
Client -> fiber router -> route-ID mapper -> guard middleware -> fiber handlers
                                                 |
                                         guardcore.Engine
                                                 |
                                   Redis (bans, rate limits)
```

- `cmd/server` - assembly: config, engine lifecycle, route registry, route-ID
  mapper, middleware order, server timeouts, and graceful shutdown
- `internal/config` - environment-driven `SecurityConfig` tuning
- `internal/routes` - fiber handlers and route groups, including `/admin/*`
  operational routes

## Quick start

```bash
cd examples/advanced_app
docker compose up --build
```

## Endpoints

| Endpoint | Notes |
|---|---|
| `GET /` | API info |
| `GET /health`, `GET /ready` | Probes, excluded from the pipeline |
| `POST /echo` | Body-bearing request; the handler reads the full body through Fiber |
| `GET /rate/burst` | `EndpointRateLimits`: 5 requests per 60 seconds |
| `GET /admin/banned` | Ban counts (requires `X-Admin-Token`) |
| `POST /admin/ban` | Body `{"ip": "...", "seconds": 300, "reason": "..."}` (requires `X-Admin-Token`) |
| `POST /admin/unban` | Body `{"ip": "..."}` (requires `X-Admin-Token`) |
| `GET /test/xss`, `GET /test/sqli` | Hostile query-param payloads; the guard blocks them before the handler runs |

## Try the security behavior

```bash
# Allowed
curl -i http://localhost:8080/

# Penetration detection blocks the payload as suspicious activity (400; the
# tuned 403 body appears once the IP crosses a ban threshold)
curl -i "http://localhost:8080/test/xss?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# Rate limiting: the sixth request in 60 seconds returns 429 with the custom body
for i in $(seq 1 6); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/rate/burst; done

# Route registry guard: missing admin token -> 400 from the engine
curl -i http://localhost:8080/admin/banned

# With the token (see ADMIN_TOKEN)
curl -i -H 'X-Admin-Token: admin-token-change-me' http://localhost:8080/admin/banned

# Manual ban, then observe the banned IP count, then unban
curl -s -X POST http://localhost:8080/admin/ban -H 'X-Admin-Token: admin-token-change-me' \
  -H 'Content-Type: application/json' -d '{"ip": "203.0.113.9", "seconds": 120}'
curl -s -H 'X-Admin-Token: admin-token-change-me' http://localhost:8080/admin/banned
curl -s -X POST http://localhost:8080/admin/unban -H 'X-Admin-Token: admin-token-change-me' \
  -H 'Content-Type: application/json' -d '{"ip": "203.0.113.9"}'
```

## Fiber notes

- **Route IDs need a mapper before the guard.** Per-route engine config is
  resolved through `RequestState.GuardRouteID`, which the adapter copies from
  the Fiber user context (`guardfiber.WithRouteID` passed to
  `c.SetContext`). Fiber runs middleware in registration order, so the mapper
  in `cmd/server/main.go` is registered before `app.Use(guard)`; a
  group-level middleware would run after the guard and the engine would never
  see the route ID. Keys are fiber route patterns (`c.FullPath()`, the
  matched route path including group prefixes), so parameterized routes map
  cleanly.
- **Groups express the URL structure, the registry expresses the policy.**
  `/admin/*` is a fiber route group, and the same paths are registered as the
  `admin` route ID on the engine's `RouteRegistry` with a `RequiredHeaders`
  guard, so the engine rejects a missing or wrong token with a 400 before any
  handler runs.
- **Client identity is the transport peer.** The adapter passes the fasthttp
  TCP peer (`RequestCtx().RemoteIP()`) to the engine and intentionally does
  not use Fiber's `c.IP()`; trusting proxy headers is core policy, configured
  through `TrustedProxies` / `TrustXForwardedProto` in `internal/config`.
  None are set here because this compose stack has no reverse proxy in front.
- The package name is `fiber`, which collides with
  `github.com/gofiber/fiber/v3`, so the adapter is imported with an explicit
  alias (`guardfiber`).

## fasthttp vs net/http (what Fiber changes for the guard)

Fiber does not run on `net/http`; it runs on
[fasthttp](https://github.com/valyala/fasthttp), and the adapter is
fasthttp-native (it shims `fiber.Ctx` rather than an `*http.Request`). Three
consequences matter when reading this example:

- **The body is fully buffered before the middleware runs.** fasthttp reads
  the whole request body into memory before the handler chain sees it, so
  the guard never has to consume or replace a stream. The net/http and Gin
  siblings wrap the body in a replay reader; here `c.Body()` simply returns
  the buffered bytes, before and after the engine scans. `MaxBodyBytes`
  therefore caps what the engine *scans*, not what the process buffers: a
  hostile client can still make fasthttp buffer up to Fiber's `BodyLimit`
  (default 4 MiB, configurable in `fiberlib.Config`) before the guard runs.
  Pair the two knobs deliberately.
- **Client IP resolves from the connection peer.** `Ctx.RequestCtx()
  .RemoteIP()` is the TCP peer address. Fiber's `c.IP()` is proxy-aware once
  `TrustProxy` plus a `ProxyHeader` are configured; the adapter deliberately
  does not use it, because trusting proxy headers is core policy (see the
  Fiber notes above).
- **`Ctx.Body()` is the Content-Encoding-decoded view.** That is what Fiber
  handlers receive, so that is what the engine scans; the raw bytes remain
  available on the ctx (`BodyRaw()`) if a future engine feature needs them.
  Note also that fasthttp itself always surfaces a default
  `Content-Type: text/plain; charset=utf-8` on responses with bodies; that is
  server behavior, not adapter translation.

## Configuration knobs demonstrated

- Global rate limiting plus per-endpoint overrides (`EndpointRateLimits`)
- Auto-banning (`AutoBanThreshold`, `AutoBanDuration`) and per-threat bans
  (`ThreatBanConfig` for `sqli` and `xss`)
- Penetration detection with all categories
- `CustomErrorResponses` for consistent block bodies (403 and 429)
- `ExcludePaths` so probes never touch the pipeline
- `LogRequestLevel` / `LogSuspiciousLevel`
- Route-scoped guards through `RouteRegistry` (`RequiredHeaders` on
  `/admin/*`)
- Cloud provider blocking (`BlockCloudProviders`, off by default)
- `OnBlock` hook: the telemetry seam for
  [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) wiring
  (comment-level guidance in `internal/config/config.go`; `EnableAgent` is
  fail-closed in this port, so the hook is the integration point)

## Intentional simplifications

- The admin gate uses `RequiredHeaders` (a real engine-enforced route guard).
  Route-level `IPWhitelist` is not consumed by the pipeline in this port yet;
  use the global `Whitelist` or edge ACLs for IP gating.
- Per-route rate limits are not read by the pipeline yet; endpoint limits are
  expressed with `EndpointRateLimits` instead.
- The `/test/*` payloads ride in query parameters because the pipeline does
  not scan request bodies in this port.
- No reverse proxy ships with this example: nginx (or your edge of choice) is
  deployment-specific, and the guard behaviour is identical behind one as
  long as the core's `TrustedProxies` is configured to match.
- The ban/unban POST bodies are parsed with `encoding/json` directly (Fiber's
  `c.Body()` returns the buffered bytes); any `Content-Type` works, and the
  live smoke still sends `application/json`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `REDIS_URL` | (unset; Redis disabled) | Shared ban/rate-limit state |
| `REDIS_PREFIX` | `guard_core:` | Redis key prefix |
| `ADMIN_TOKEN` | `admin-token-change-me` | `X-Admin-Token` value for `/admin/*` |
| `RATE_LIMIT` / `RATE_LIMIT_WINDOW` | `30` / `60` | Global rate limit |
| `AUTO_BAN_THRESHOLD` / `AUTO_BAN_DURATION` | `5` / `300` | Auto-ban policy |
| `BLOCK_CLOUD_PROVIDERS` | empty | Comma-separated providers (e.g. `AWS,GCP`) |
| `LOG_REQUEST_LEVEL` / `LOG_SUSPICIOUS_LEVEL` | `INFO` / `WARNING` | Log levels |

## Key differences from simple_app

| Feature | simple_app | advanced_app |
|---|---|---|
| Layout | single `main.go` | `cmd/` + `internal/` packages |
| Docker build | single stage | multi-stage build, non-root user |
| Route registry | not used | `admin` route with `RequiredHeaders` |
| Admin/ops routes | none | ban, unban, ban counts |
| Route-ID mapper | not used | pattern-to-ID mapper before the guard |
| Threat bans | `xss` demo threshold of 1 | tuned `sqli` / `xss` thresholds |
| Shutdown | `app.Listen` | `ListenConfig.GracefulContext` with drain timeout |
| Resource limits | none | CPU and memory limits per service |

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
