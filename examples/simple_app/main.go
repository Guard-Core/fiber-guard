// Command simple_app is a minimal guarded Fiber server. The Fiber bridging
// lives in the fiber-guard adapter (this repository) and every security
// decision comes from the guard-core-go engine, so the demonstration wiring
// is the canonical one:
//
//	SecurityConfig -> NewEngine -> Initialize -> guardfiber.New -> app.Use
//
// Unlike guard-core-go's own simple_app, no request shim is written here: the
// adapter performs request translation, bounded body scanning, exact verdict
// translation, and fail-closed handling.
package main

import (
	"log"
	"os"
	"strings"

	fiberlib "github.com/gofiber/fiber/v3"
	recovermw "github.com/gofiber/fiber/v3/middleware/recover"
	guardfiber "github.com/rennf93/fiber-guard"
	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
)

func main() {
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		// Rate limiting: global 30 req/60s per client, with a strict
		// per-endpoint override used by the demo and the live smoke test.
		c.EnableRateLimiting = true
		c.RateLimit = 30
		c.RateLimitWindow = 60
		c.EndpointRateLimits = map[string]guardcore.RateLimitEntry{
			"/rate/strict": {Requests: 1, Window: 10},
		}

		// IP banning: 5 violations in the window earns a 5 minute ban.
		c.EnableIPBanning = true
		c.AutoBanThreshold = 5
		c.AutoBanDuration = 300

		// Demo determinism: a single xss violation bans the client right
		// away, so the live smoke can assert the 200 -> 403 transition
		// without replaying a loop. Use realistic thresholds in production.
		c.ThreatBanConfig = map[string]guardcore.ThreatBanEntry{
			"xss": {Threshold: 1, Duration: 300},
		}

		// Penetration detection: all categories, default thresholds.
		c.EnablePenetrationDetection = true

		// The Python engine automatically skips ssrf scanning for address
		// headers (host, x-forwarded-for, x-real-ip, ...). This port does
		// not apply that built-in exclusion yet, and the Fiber adapter
		// forwards fasthttp's explicit Host header (see request.go), so
		// mirror the exclusion here; otherwise a plain "Host: localhost"
		// request is flagged as ssrf. Excluding these headers only narrows
		// detection scanning, it does not affect trusted-proxy client IP
		// resolution.
		c.ExcludedDetectionHeaders = map[string]bool{
			"host": true, "origin": true, "via": true,
			"x-forwarded-for": true, "x-forwarded-host": true,
			"x-real-ip": true, "x-client-ip": true,
			"x-cluster-client-ip": true, "cf-connecting-ip": true,
			"true-client-ip": true, "fly-client-ip": true,
			"x-envoy-external-address": true,
		}

		// Blocked user agents (regex patterns).
		c.BlockedUserAgents = []string{"badbot", "evil-crawler", "sqlmap"}

		// Custom block bodies, keyed by status code.
		c.CustomErrorResponses = map[int]string{
			403: "Blocked by fiber-guard",
		}

		// Paths the pipeline never sees.
		c.ExcludePaths = []string{
			"/docs", "/redoc", "/openapi.json", "/favicon.ico", "/static", "/health",
		}

		// OnBlock is the telemetry seam of this port. Guard Agent
		// integration is not implemented in guard-core-go yet (setting
		// EnableAgent fails config validation), so wire the agent from
		// here: forward these payloads to guard-agent-go
		// (https://github.com/Guard-Core/guard-agent-go) once its event
		// pipeline accepts engine events. The payload carries check_name,
		// reason, trigger_info, passive_mode, client_ip, path, method, and
		// status_code.
		c.OnBlock = func(req guardcore.Request, payload map[string]any) {
			log.Printf("guard blocked %s %s from %s via %s: %s",
				payload["method"], payload["path"], payload["client_ip"],
				payload["check_name"], payload["reason"])
		}

		// Redis: enabled when REDIS_URL is set (docker compose sets it to
		// redis://redis:6379). Without Redis the managers fall back to
		// in-process state, which is fine for a demo but not for replicas.
		if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
			c.EnableRedis = true
			c.RedisURL = redisURL
		} else {
			c.EnableRedis = false
		}
		if prefix := os.Getenv("REDIS_PREFIX"); prefix != "" {
			c.RedisPrefix = prefix
		}
	})
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	// Idempotent; connects Redis when enabled and primes cloud IP ranges.
	if err := engine.Initialize(); err != nil {
		log.Fatalf("initialize: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			log.Printf("engine close: %v", err)
		}
	}()

	// New returns a fiber.Handler, so the guard composes with app.Use and
	// can sit anywhere in a chain. The options below are the defaults,
	// made explicit: bound the bytes the engine scans, and log fail-closed
	// malfunctions through the standard logger.
	guard, err := guardfiber.New(engine,
		guardfiber.WithMaxBodyBytes(guardfiber.DefaultMaxBodyBytes),
		guardfiber.WithLogger(log.Default()),
	)
	if err != nil {
		log.Fatalf("middleware: %v", err)
	}

	app := fiberlib.New()
	// Recovery stays outermost so handler panics are contained; the guard
	// runs next so blocked requests never reach another middleware. Fiber
	// has no explicit abort call: the guard writes the verdict and returns
	// without calling c.Next(), which stops the chain.
	app.Use(recovermw.New())
	app.Use(guard)
	app.Get("/", info)
	app.Get("/health", health)
	app.Post("/echo", echo)
	app.Get("/rate/strict", strict)
	app.Get("/search", search)

	log.Println("simple_app listening on :8080")
	log.Fatal(app.Listen(":8080"))
}

func info(c fiberlib.Ctx) error {
	return c.JSON(fiberlib.Map{
		"app":       "fiber-guard simple_app",
		"endpoints": []string{"/health", "/echo (POST)", "/rate/strict", "/search?q="},
	})
}

func health(c fiberlib.Ctx) error {
	return c.JSON(fiberlib.Map{"status": "ok"})
}

// echo proves the adapter's body contract: fasthttp buffers the full body
// before the middleware runs, the engine scans only the bounded prefix, and
// the handler reads the full body straight from Fiber (no replay wrapper).
func echo(c fiberlib.Ctx) error {
	if c.Method() != fiberlib.MethodPost {
		return c.Status(fiberlib.StatusMethodNotAllowed).SendString("method not allowed")
	}
	body := c.Body()
	return c.JSON(fiberlib.Map{"echo": true, "bytes": len(body)})
}

func strict(c fiberlib.Ctx) error {
	return c.JSON(fiberlib.Map{
		"endpoint": "/rate/strict",
		"limit":    "1 request per 10 seconds",
	})
}

func search(c fiberlib.Ctx) error {
	q := c.Query("q")
	if strings.ContainsAny(q, "<'") {
		// The engine should have blocked requests that reach this handler
		// with hostile input; treat this as defense in depth and never echo
		// or log the payload.
		return c.Status(fiberlib.StatusForbidden).SendString("Blocked by fiber-guard")
	}
	return c.JSON(fiberlib.Map{"query": q, "results": []string{}})
}
