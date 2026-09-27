# fiber-guard

Fiber middleware adapter for [guard-core-go](https://github.com/rennf93/guard-core-go). Translates `fiber.Ctx` into the guardcore request surface, runs the engine, and translates verdicts to exact Fiber responses (status, headers, body, then stop). Works with any `fiber.App` chain via `app.Use`. Unlike the net/http and Gin siblings, this adapter is fasthttp-native: Fiber runs on [fasthttp](https://github.com/valyala/fasthttp), not `net/http`, so the adapter shims `fiber.Ctx` directly.

Docs: <https://rennf93.github.io/fiber-guard/>

## Install

Released: `v1.1.0` on the Go module proxy. The engine stays pinned to the `guard-core-go` master pseudo-version below until the synchronized 4.2.0 train retags it:

```
go get github.com/rennf93/fiber-guard@v1.1.0 github.com/rennf93/guard-core-go/v4@v4.0.5-0.20260926230539-e39ac203568b
```

The package name is `fiber`, which collides with `github.com/gofiber/fiber/v3` (also package `fiber`), so import the adapter with an explicit alias such as `guardfiber`.

## Usage

```go
package main

import (
	"log"

	fiberlib "github.com/gofiber/fiber/v3"
	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
	guardfiber "github.com/rennf93/fiber-guard"
)

func main() {
	cfg := guardcore.DefaultSecurityConfig()
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := engine.Initialize(); err != nil {
		log.Fatal(err)
	}

	guard, err := guardfiber.New(engine)
	if err != nil {
		log.Fatal(err)
	}

	app := fiberlib.New()
	app.Use(guard)
	app.Get("/", func(c fiberlib.Ctx) error {
		return c.SendString("ok")
	})

	log.Fatal(app.Listen(":8080"))
}
```

Options: `guardfiber.WithMaxBodyBytes(n)` bounds the body bytes the engine scans (default 262144), `guardfiber.WithLogger(l)` swaps the fail-closed logger. Route-level configuration uses `engine.Routes.Register` plus `guardfiber.WithRouteID(ctx, id)` on the Fiber user context (set `c.SetContext(...)` in a middleware registered before the guard).

Every engine `SecurityConfig` field is reachable through this adapter: global tuning (behavior rules with `BehaviorScanResponseBody` and the inspect-bytes budget, the geo lifecycle with `IPInfoToken`/`OnGeoEvent`, CORS, security headers, custom error bodies) goes through the `SecurityConfig` you hand to `guardcore.NewEngine`, per-route detection exclusions and per-route behavior/IP rules through `engine.Routes.Register`. On every pass-through response the adapter merges `Engine.ResponseHeaders()` with `Engine.CORSResponseHeaders(req)` and reports the response (status plus the leading inspect-budget bytes of Fiber's buffered body when `BehaviorScanResponseBody` is on) to `Engine.ProcessResponse` for the behavioral return rules. See [docs/configuration.md](docs/configuration.md).

Engine malfunctions fail closed with a 500. Detection covers at most the first `MaxBodyBytes` of the body; payloads beyond the bound are not scanned, and the full body still reaches your handler untouched.

Two fasthttp realities to know: the request body is fully buffered in memory before the middleware runs (Fiber's `BodyLimit` config, default 4 MiB, is the network-level bound), and `Body()` returns the Content-Encoding-decoded view, so that is what the engine scans. Client identity is the fasthttp TCP peer IP, not `c.IP()` proxy resolution.

## Development

The middleware consumes the core as a normal module dependency, currently pinned to the guard-core-go master surface (`v4.0.5-0.20260926230539-e39ac203568b`, the behavior-rules / geo-lifecycle / route-detection-exclusions wave); no `replace` directive is used or needed. For cross-repo work on the core itself, add a temporary local `replace` line in your own checkout and drop it before committing.

Integration tests run against real Redis:

```
REDIS_HOST=127.0.0.1 go test -tags integration ./...
```

## License

MIT
