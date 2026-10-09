Release Notes
=============

___

v1.4.0 (2026-10-09)
-------------------

The websocket guard, the status route and the adapter lifecycle surface (guard-core-go v4.3.2 floor)
----------------------------------------------------------------------------------------------------

### Added

- **The websocket handshake guard** (#24): `GuardWebSocket(engine, c)` ports the reference websocket guard onto the Fiber adapter, running the engine's handshake checks over the upgrade request (identity resolution, the fail-secure unknown-address close, the ban probe, the `is_ip_allowed` verdict, the ws rate limit, and the penetration detection pass sharing the HTTP pipeline's suspicious counts). A nil result allows the upgrade; a non-nil reason closes it; a nil engine fails closed with the security-check-failed reason. `WebSocketHTTPStatus` maps a close reason onto the HTTP status an upgrade rejection carries (503 try-again-later, 403 policy violation), and the ws request shim mirrors the reference `_WebSocketGuardRequest` (method WEBSOCKET, empty body, repeated headers joined with a comma, fresh request state).
- **The reference status route** (#25): `AddStatusRoute(app, engine, path)` registers a GET handler serving the engine's initialization snapshot JSON (cloud_providers ready/last_refreshed/entries per provider, geo_ip null or the configured resolver's status, redis enabled plus a live O(1) probe with the failure string) at `DefaultStatusPath` (`/_guard/status`) by default, never mutating engine state, the sibling adapters' `AddStatusRoute` over Fiber's router.
- **The adapter lifecycle surface** (#26): the fastapi-guard middleware lifecycle ops (the FEATURE_MATRIX_GO adapter row's PARTIAL/MISSING entries) as explicit functions over the engine handle (the same seam as `GuardWebSocket` and `AddStatusRoute`): `MarkInitialized` (a warmed engine makes `Initialize` a no-op), `GetInitializationStatus` (the payload `AddStatusRoute` serves), `Reset` (the rate limiter's windows, redis and in-memory), `AgentStats` (enabled/degraded merged with the wired handler's stats), and `RefreshCloudIPRanges` (the redis-backed refresh at the configured TTL, the reference `cloud_handler.refresh_async`, or the in-memory refresh; no blocked providers is the reference's no-op early return).

### Changed

- **Raised the engine floor to `github.com/rennf93/guard-core-go/v4 v4.3.2`, the adapter-parity release.** The v4.3.2 engine carries the ReDoS static-safety trio with the pattern_safety corpus going registry-free (94/94, 0 divergences), the sus-patterns runtime registry with the `pattern_detected` envelope and real dynamic-rules application, the `custom_response_modifier` response pass (`Engine.ModifyResponse` exposes it to this adapter for pass-through composition), the websocket guard surface `GuardWebSocket` drives with suspicious counts shared with the HTTP pipeline, the fifteen SecurityConfig knobs with the performance-monitor wiring, and the lifecycle/state surface the functions above call (manager exports, `GeoIPManager.IsInitialized`, the cross-instance middleware state registry, the engine side of `MarkInitialized`/`AgentStats`). The floor also brings `redis/go-redis/v9` v9.23.0 transitively, clearing the stdlib-adjacent x/sys exposure; govulncheck stays clean. Everything else flows through the unchanged middleware surface.
- **Dependency bumps**: `github.com/valyala/fasthttp` to v1.75.0 in the go-modules group (#27), and `golang.org/x/net` pinned at the v0.60.0 explicit indirect floor (#29), clearing the five 2026 http2 findings (GO-2026-6603/6610/6611/6612/6617) reachable through the x/net http2 paths (`FrameType.String`, `Transport.RoundTrip`).
- **Post-transfer metadata sweep** (1ab85c5): repo URLs, docs links, and ecosystem references point at the Guard-Core org, and the upstream-drift suite checks out `Guard-Core/guard-core-go@master`. Module paths, Go imports, and the CHANGELOG history line are deliberately unchanged.

___

v1.3.0 (2026-10-01)
-------------------

guard-core-go v4.3.0 floor (the corpus-parity engine)
-----------------------------------------------------

### Changed

- **Raised the engine floor to `github.com/rennf93/guard-core-go/v4 v4.3.0`, the corpus-parity release.** The v4.3.0 engine is validated against the full conformance corpus: the pattern_safety, events and redis_interop suite kinds now run against the real engine alongside detect and pipeline (fail-closed baselines), the spec 12 observable event stream is ported (security event bus, metrics collector, dynamic-rules agent pipeline, the emission fidelity wave that closes the events surface to reference parity at 32 of 38 cases), plus the detection performance monitor, the security-headers Redis cache with the cross-worker sync contract, and the manager-level geo country verdict (`GeoIPManager.CheckCountryAccess`). Everything flows to the adapter through the unchanged middleware surface: agent integrations receive the new event stream via the existing handler hooks, and the engine-level changes require no adapter code. The module's `go` directive follows the engine to 1.26.0 (the engine's toolchain floor), and the CI matrix (ci.yml and release.yml), the example-app smoke images and the Makefile's GO_IMAGE move to go 1.26 with it, mirroring the engine's own go 1.26 floor wave (guard-core-go #36).
- **The query-parameter shim iterates the fasthttp args iterator with a range over `All()`** instead of the callback-based `VisitAll` (the staticcheck cleanup ahead of the new staticcheck gate, #21); behavior is identical (first value wins per key).

### Added

- **A hard 100% coverage gate wired into CI** (#22): the adapter surface is fully covered (`coverage_test.go` drives the shim and middleware paths the pipeline exercises), and the gate (`check_coverage.sh`) fails closed on a missing or empty profile and refuses anything under 100% total.
- **staticcheck joins the CI gates** (#21) with the findings fixed ahead of the gate.
- **The upstream-drift suite runs on go 1.26** (#20) to match engine master's toolchain floor.
- **The guard-core process baseline** (#21): hygiene files (SECURITY, CONTRIBUTING, Code of Conduct, funding, issue and PR templates), dependabot, the labeler and scheduled lint.

___

v1.2.0 (2026-09-27)
-------------------

guard-core-go v4.2.0 floor (the parity engine)
----------------------------------------------

### Changed

- **Raised the engine floor to `github.com/rennf93/guard-core-go/v4 v4.2.0`, replacing the master pseudo-version pin with the real parity tag.** The v4.2.0 engine is the parity release validated against the shared conformance corpus (spec 4.1.0, 219 cases; pipeline gate 35 passed, 0 failed, 0 xfail, 0 config divergences) and carries everything the pseudo-version pin already exercised plus the full feature surface: behavior rules (global_behavior_rules, per-route BehaviorRules, Engine.ProcessResponse return rules), the IPInfo geo lifecycle with OnGeoEvent (country_blocked, geo_lookup_failed, decorator_violation), per-route detection exclusions and enable_suspicious_detection, Retry-After from the tripped rate-limit tier window, the corrected CORS response surface (Allow-Methods/Headers, 3600 Max-Age, wildcard plus credentials downgraded at policy resolution), and the reference-shape passive on_block hook payloads (empty trigger_info, null status_code, inline ip_security/deny dispatch). The intermediate master pin (v4.0.5-0.20260927055209) existed only to pick up the 4.1.0 passive on_block contract ahead of the tag; v4.2.0 supersedes it.

___

v1.1.0 (2026-09-26)
-------------------

Security headers on pass-through responses
------------------------------------------

### Added

- **Security headers on every pass-through response.** The adapter applies the engine's `ResponseHeaders()` set in one loop before the handler writes, so clean responses carry the same default header set as blocked ones (mirroring the engine's `process_response`). Disabling `SecurityHeaders` restores the header-free pass (fasthttp's default `Content-Type` aside), and config overrides plus custom headers flow through the adapter untouched.

___

v1.0.1 (2026-09-26)
-------------------

guard-core-go v4.1.0 floor bump
-------------------------------

### Changed

- **Raised the engine floor to `github.com/rennf93/guard-core-go/v4 v4.1.0`.** Blocked verdicts now carry the engine's default security headers engine-side, and the adapter's verdict translation is unchanged. The floor also carries the engine's per-route IP allow/block lists, `exempt_ips`, geo country blocking, and CORS support. The fiber suite never pinned the header-free blocked response (fasthttp owns `Content-Type`, and only routing headers such as `Location` are asserted against), so no adapter assertion changes were needed.

___

v1.0.0 (2026-09-24)
-------------------

First stable release (v1.0.0)
-----------------------------

### Added

- **The first stable release of fiber-guard, the net/http middleware adapter for the guard-core-go engine.** It translates `fiber.Ctx` into the guardcore request surface, runs the engine, and translates verdicts to exact HTTP responses. Works with any `fiber.App` chain via `app.Use`. Unlike the net/http and Gin siblings, this adapter is fasthttp-native: Fiber runs on fasthttp, not `net/http`, so the adapter shims `fiber.Ctx` directly.
- **17/17 security checks parity with guard-core 4.0.4**, covering suspicious activity detection, penetration attempts, IP bans and allow lists, cloud provider detection, rate limiting, HTTPS enforcement, required headers, referrer policy, user agent filtering, and route-level configuration, with binary-noise gates on the detection engine.
- **Fail-closed behavior on engine malfunctions**: any engine error answers 500 instead of letting the request through. Detection covers at most the first `MaxBodyBytes` of the body (default 262144, tunable via `guardfiber.WithMaxBodyBytes`); payloads beyond the bound are not scanned, and the full body still reaches your handler untouched.
- **Route-level configuration** via `engine.Routes.Register` plus `guardfiber.WithRouteID(ctx, id)` on the Fiber user context (set `c.SetContext(...)` in a middleware registered before the guard), and a swappable fail-closed logger via `guardfiber.WithLogger(l)`.
- **fasthttp-native shimming with documented realities**: the request body is fully buffered in memory before the middleware runs (Fiber `BodyLimit`, default 4 MiB, is the network-level bound), `Body()` returns the Content-Encoding-decoded view (that is what the engine scans), and client identity is the fasthttp TCP peer IP, not `c.IP()` proxy resolution.
- **Documentation site** (MkDocs: index and usage/configuration pages), simple and advanced example apps, and a dockerized live smoke workflow over the example apps.

### Changed

- **Migrated to the guard-core-go `/v4` module path.** The dependency is now `github.com/rennf93/guard-core-go/v4 v4.0.4` and every import uses `github.com/rennf93/guard-core-go/v4/guardcore`. The previous `github.com/rennf93/guard-core-go v0.1.0` pre-release is retired.
- **Release engineering harmonized with guard-core-go**: a dockerized `Makefile` (install, test, lint, clean, bump-version) and a stdlib-only `.github/scripts/bump_version.py` that scaffolds this changelog; the git tag is the version.
- **Upstream drift guard, demo container publishing, and community workflows** from the parity polish: a daily test run of the adapter suite against guard-core-go@master, a container-release workflow for the demo image, docs publishing to GitHub Pages, plus labeling, staleness, and greetings workflows.

___
