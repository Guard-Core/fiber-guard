# Configuration

The adapter has exactly two options (`WithMaxBodyBytes`, `WithLogger`); all
security tuning is engine configuration. See the
[guard-core-go configuration reference](https://rennf93.github.io/guard-core-go/configuration/)
for the full `SecurityConfig` surface.

## Minimal tuned setup

```go
cfg := guardcore.DefaultSecurityConfig()
cfg.EnableRateLimiting = true
cfg.RateLimit = 30
cfg.RateLimitWindow = 60
cfg.EndpointRateLimits = map[string]guardcore.RateLimitEntry{
    "/rate/strict": {Requests: 1, Window: 10},
}
cfg.EnableIPBanning = true
cfg.AutoBanThreshold = 5
cfg.AutoBanDuration = 300
cfg.CustomErrorResponses = map[int]string{
    403: "Blocked by fiber-guard",
}
```

## Address headers

The Python engine skips ssrf scanning for address headers (`host`,
`x-forwarded-for`, `x-real-ip`, ...) automatically. The Go engine does not
apply that built-in exclusion yet, so mirror it explicitly when clients can
send internal hostnames; the Fiber adapter forwards fasthttp's explicit Host
header, so `host` must be in the set:

```go
cfg.ExcludedDetectionHeaders = map[string]bool{
    "host": true, "origin": true, "via": true,
    "x-forwarded-for": true, "x-forwarded-host": true,
    "x-real-ip": true, "x-client-ip": true,
}
```

## Redis

Distributed bans and rate limits require Redis:

```go
cfg.EnableRedis = true
cfg.RedisURL = os.Getenv("REDIS_URL") // e.g. redis://redis:6379
cfg.RedisPrefix = "fiber_guard:"
```

Without Redis the managers fall back to in-process state, which does not
share across replicas.

## Body inspection

`WithMaxBodyBytes` bounds what the detector sees. Bodies larger than the
limit are still forwarded to your handler in full (fasthttp buffers the whole
body before the middleware runs); only the inspected prefix is truncated. The
default matches the engine's `MaxBodyInspectBytes` (262144).

## Trusted proxies

The adapter resolves the client from the fasthttp transport peer
(`RequestCtx().RemoteIP()`), never from `c.IP()`: with TrustProxy plus a
ProxyHeader configured, Fiber would resolve the client from proxy headers,
and trusting proxy headers is policy the engine owns. When behind a reverse
proxy, trust only the proxy hop so the engine resolves the real client IP
from forwarded headers:

```go
cfg.TrustedProxies = []string{"172.16.0.0/12", "10.0.0.0/8"}
cfg.TrustedProxyDepth = 1
```

## Behavior rules

The engine's behavioral surface is configurable through the global fields:

```go
cfg.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
    {RuleType: "usage", Threshold: 100, Window: 3600, Action: "ban"},
}
cfg.BehaviorScanResponseBody = true
cfg.BehaviorMaxResponseBodyInspectBytes = 262144
```

`BehaviorScanResponseBody` gates return-pattern rules that read the response
body (`regex:`, `json:`, or bare substring patterns; `status:` patterns work
without it). With the flag on, the adapter captures the leading
`BehaviorMaxResponseBodyInspectBytes` of Fiber's buffered response body and
reports status code plus captured prefix to `Engine.ProcessResponse` after
your handler runs, mirroring the reference response factory's behavioral
phase. Return rules never modify the response. Note: Fiber buffers the response, so every handler response is observed; no
framework limitation applies.

## Geo lifecycle

Country rules resolve through the engine's geo lifecycle. A token enables the
full IPInfo download/refresh lifecycle; a database path keeps local-file
mode. `OnGeoEvent` receives `country_blocked`, `geo_lookup_failed`, and
`decorator_violation` events:

```go
cfg.IPInfoToken = os.Getenv("IPINFO_TOKEN")
cfg.IPInfoMaxAge = 86400 // 0 falls back to the reference default
cfg.BlockedCountries = []string{"CN"}
cfg.OnGeoEvent = func(ev guardcore.GeoEvent) { ... }
```

Route-level country rules (`RouteConfig.BlockedCountries` /
`WhitelistCountries`) emit the same events through the same hook.

## Per-route detection exclusions

Route configuration lives in the engine registry and reaches the middleware
through `guardfiber.WithRouteID` (see [Usage](usage.md)). Every
`guardcore.RouteConfig` field is reachable, including the per-route detection
exclusion surface:

```go
engine.Routes.Register("search", func(rc *guardcore.RouteConfig) {
    rc.ExcludedDetectionParams = map[string]bool{"q": true}
    rc.ExcludedDetectionHeaders = map[string]bool{"referer": true}
    rc.ExcludedDetectionBodyFields = map[string]bool{"note": true}
    rc.EnabledDetectionCategories = []string{"xss", "sqli"}
    scanOff := false
    rc.DetectionScanBody = &scanOff
    rc.BehaviorRules = []guardcore.BehaviorRuleConfig{
        {RuleType: "usage", Threshold: 10, Window: 60, Action: "ban"},
    }
})
```

## CORS

Set `cfg.EnableCORS = true` (plus any `CORSAllowOrigins`, `CORSAllowMethods`,
`CORSAllowHeaders`, `CORSAllowCredentials`, `CORSExposeHeaders`,
`CORSMaxAge` tuning). Preflights are short-circuited by the engine through
`guardfiber.New`, blocked responses carry the CORS headers over the
security-header set, and the adapter merges
`Engine.CORSResponseHeaders(req)` into every pass-through response.

## Custom error bodies

`cfg.CustomErrorResponses` replaces the body of any engine verdict status
code; the status code and security headers stay engine-owned.
