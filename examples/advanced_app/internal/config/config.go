// Package config builds the engine's SecurityConfig from environment
// variables with production-oriented defaults. Keeping config in one place
// mirrors the config module of the Python advanced example.
package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
)

// New builds a tuned SecurityConfig from the environment.
func New() (*guardcore.SecurityConfig, error) {
	return guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		// Client identity: the fiber-guard adapter passes the fasthttp
		// transport peer (RequestCtx().RemoteIP()) to the engine, exactly
		// like the net/http and Gin sibling adapters. Fiber's c.IP() is
		// intentionally not used by the adapter: with TrustProxy plus a
		// ProxyHeader configured it resolves the client from proxy headers,
		// and trusting proxy headers is policy. The core owns that policy
		// through TrustedProxies / TrustXForwardedProto. None are set here
		// because this compose stack has no reverse proxy in front; if you
		// front this app with one, configure those two fields here.

		// Rate limiting: global 30 req/60s per client, plus per-endpoint
		// overrides. /rate/burst is expressed through EndpointRateLimits
		// because route-scoped rate limits are not read by the pipeline in
		// this port yet.
		c.EnableRateLimiting = true
		c.RateLimit = intEnv("RATE_LIMIT", 30)
		c.RateLimitWindow = intEnv("RATE_LIMIT_WINDOW", 60)
		c.EndpointRateLimits = map[string]guardcore.RateLimitEntry{
			"/rate/burst": {Requests: 5, Window: 60},
		}

		// IP banning: five violations earn a five minute ban, and hostile
		// categories can ban earlier through per-threat thresholds.
		c.EnableIPBanning = true
		c.AutoBanThreshold = intEnv("AUTO_BAN_THRESHOLD", 5)
		c.AutoBanDuration = intEnv("AUTO_BAN_DURATION", 300)
		c.ThreatBanConfig = map[string]guardcore.ThreatBanEntry{
			"sqli": {Threshold: 3, Duration: 1800},
			"xss":  {Threshold: 5, Duration: 600},
		}

		// Detection: every category, default detector tuning.
		c.EnablePenetrationDetection = true

		// Address headers (host, x-forwarded-for, x-real-ip, ...) are already
		// excluded from detection by the engine's built-in default set
		// (guardcore.DefaultExcludedHeaders, the reference's
		// _DEFAULT_EXCLUDED_HEADERS), so a plain "Host: localhost" request is
		// not flagged and no ExcludedDetectionHeaders entry is needed here.
		// ExcludedDetectionHeaders only adds names on top of that default.

		// Edge filters.
		c.BlockedUserAgents = []string{"badbot", "evil-crawler", "sqlmap"}
		c.BlockCloudProviders = splitCSV(os.Getenv("BLOCK_CLOUD_PROVIDERS"))

		// Consistent block bodies for every verdict the pipeline returns.
		c.CustomErrorResponses = map[int]string{
			403: "Blocked by fiber-guard (advanced example)",
			429: "Rate limit exceeded, slow down",
		}

		// Liveness/readiness probes never reach the pipeline.
		c.ExcludePaths = []string{
			"/docs", "/redoc", "/openapi.json", "/favicon.ico", "/static",
			"/health", "/ready",
		}

		// Logging levels for request and suspicious-activity logs.
		c.LogRequestLevel = EnvOr("LOG_REQUEST_LEVEL", "INFO")
		c.LogSuspiciousLevel = EnvOr("LOG_SUSPICIOUS_LEVEL", "WARNING")

		// OnBlock is the engine's block-event hook (check_name, reason,
		// trigger_info, passive_mode, client_ip, path, method, status_code).
		// Agent telemetry rides a different seam: EnableAgent validates, and
		// the engine streams events and metrics to the guardcore.AgentHandler
		// set in AgentHandler (SendEvent/SendMetric). Without a handler the
		// engine logs that the agent cannot initialize and continues without
		// it (AgentStrict makes NewEngine fail instead), so this example keeps
		// EnableAgent off and only logs blocks. guard-agent-go takes a
		// context and its own event types, so it needs a small bridge to
		// satisfy guardcore.AgentHandler.
		c.OnBlock = func(req guardcore.Request, payload map[string]any) {
			log.Printf("guard blocked %s %s from %s via %s: %s",
				payload["method"], payload["path"], payload["client_ip"],
				payload["check_name"], payload["reason"])
		}

		// Redis is required for shared state across replicas; compose wires
		// it in. RedisFailOpen stays false (the zero value), keeping the
		// default fail-secure posture.
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
}

// EnvOr reads an environment variable with a fallback; exported because the
// server assembly needs the same resolution for its own knobs.
func EnvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func intEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}
