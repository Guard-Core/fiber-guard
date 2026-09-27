# fiber-guard

`fiber-guard` is the official Fiber v3 adapter for
[guard-core-go](https://github.com/rennf93/guard-core-go), the Go port of the
guard-core security engine. It wraps any Fiber app with the full engine
pipeline: penetration detection, rate limiting, IP banning, and verdict
responses.

All security logic lives in the engine; this package is a thin shim that
translates `fiber.Ctx` into `guardcore.Request`, runs the engine, and writes
the block verdict when one arrives.

## Installation

```bash
go get github.com/rennf93/fiber-guard@v1.1.0 github.com/rennf93/guard-core-go/v4@v4.0.5-0.20260926230539-e39ac203568b
```

Requires Go 1.25 or later and Fiber v3.5 or later.

## Quick start

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
	defer func() { _ = engine.Close() }()

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

## What the shim handles

- Client identity: `RequestCtx().RemoteIP()` from the fasthttp transport,
  with trusted-proxy resolution performed by the engine
  (`SecurityConfig.TrustedProxies`). Fiber's `c.IP()` is intentionally not
  used: with TrustProxy plus a ProxyHeader configured it resolves the client
  from proxy headers, and trusting proxy headers is policy the core owns.
- Headers: first value per key, read from
  `RequestCtx().Request.Header.All()`
- Body: fasthttp buffers the full body before the middleware runs, the engine
  sees only the first `maxBodyBytes` bytes, and the handler reads the full,
  untouched body straight from Fiber
- Route IDs: read from the Fiber user context (see [Usage](usage.md))
- Fail-closed: engine panics become `500` with a fixed, non-leaky message

See [Configuration](configuration.md) for engine tuning and the
[examples](https://github.com/rennf93/fiber-guard/tree/master/examples) for
runnable apps.
