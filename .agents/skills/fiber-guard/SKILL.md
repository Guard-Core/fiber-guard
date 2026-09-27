---
name: fiber-guard
description: Fiber middleware adapter for guard-core-go. Use when adding Guard security (IP filtering, rate limiting, penetration detection, security headers) to a Fiber v3 app backed by fasthttp, configuring New() options (WithMaxBodyBytes, WithLogger, WithRouteID), wiring the fasthttp-native request shim, or diagnosing verdict translation and fail-secure 500 behavior in Fiber middleware. Covers setup, the fasthttp-vs-net/http shim differences, and integration with guard-core-go.
---

## Quick Reference

- Module: github.com/rennf93/fiber-guard, package fiber, go 1.25.0, MIT
- Core: github.com/rennf93/guard-core-go/v4 v4.0.5-0.20260926230539-e39ac203568b (normal require)
- Surface: New(app *fiber.App, opts ...Option) (fiber.Handler, error); Options: WithMaxBodyBytes (default 262144), WithLogger, WithRouteID

## Installation

```bash
go get github.com/rennf93/fiber-guard@v1.1.0
```

## Setup

```go
app := fiber.New()
engine, err := guardcore.NewEngine(guardcore.DefaultConfig())
if err != nil { panic(err) }
guard, err := fiberguard.New(app, fiberguard.WithMaxBodyBytes(262144))
if err != nil { panic(err) }
app.Use(guard)
```

## fasthttp shim notes

Fiber v3 is not net/http based: the shim implements guardcore.Request directly over fiber.Ctx. Peer IP comes from Ctx.IP() (documented policy note; XFF handling is the core's job). Bodies are fully buffered by fasthttp, so the MaxBodyBytes cap bounds what is scanned, not what is read. Abort semantics: Fiber middleware blocks by returning without c.Next().

## Footguns

- Register the guard before any route that needs protection; WithRouteID rides fiber.Ctx locals set by earlier middleware.
- Do not add security logic here - it belongs in guard-core-go; this adapter only shims requests and translates verdicts.

## Related Projects

guard-core-go (engine), nethttp-guard and gin-guard (sibling adapters), guard-agent-go v3.0.2 (telemetry).
