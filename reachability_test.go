package fiber

// Reachability tests: every engine SecurityConfig surface must be
// configurable through this adapter's public API and observable in the
// middleware behavior. Configure via guardcore.SecurityConfig (the adapter's
// config idiom: the user builds the engine and hands it to New), attach
// route IDs via WithRouteID, and observe the verdicts and headers the
// adapter produces.

import (
	"strings"
	"testing"

	fiberlib "github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const testRemoteAddr = "192.0.2.1:1234"

type fakeCountryResolver struct {
	country string
}

func (f fakeCountryResolver) GetCountry(string) (string, bool) {
	if f.country == "" {
		return "", false
	}
	return f.country, true
}

// serveWithRouteID runs a request through the guard with an engine route ID
// attached via WithRouteID, the fiber adapter's route-ID path: a mapper
// middleware registered before the guard wraps the request context.
func serveWithRouteID(t *testing.T, engine *guardcore.Engine, routeID, target string, handlerBody ...string) *fasthttp.Response {
	t.Helper()
	guard, err := New(engine)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	app := fiberlib.New()
	app.Use(func(c fiberlib.Ctx) error {
		if routeID != "" {
			c.SetContext(WithRouteID(c.RequestCtx(), routeID))
		}
		return c.Next()
	})
	app.Use(guard)
	app.All("/*", func(c fiberlib.Ctx) error {
		body := "handler-body"
		if len(handlerBody) > 0 {
			body = handlerBody[0]
		}
		return c.SendString(body)
	})
	return runFiberApp(t, app, testRemoteAddr, newReq("GET", target, "", nil))
}

func responseString(resp *fasthttp.Response) string {
	return strings.TrimSpace(string(resp.Body()))
}

// Global behavior rules: a route usage rule (route_config.behavior_rules)
// bans the client once the threshold trips, and the adapter surfaces the
// engine's 403 "IP address banned" verdict on the next request.
func TestReachabilityRouteBehaviorUsageRuleBans(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.EnableRateLimiting = false
		c.GlobalBehaviorRules = nil
	})
	engine.Routes.Register("limited", func(rc *guardcore.RouteConfig) {
		rc.BehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "usage", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	// Two requests trip threshold 1 engine-side (strictly greater): both
	// pass, the ban lands on the usage rule, and the next request is 403.
	for i := 0; i < 2; i++ {
		resp := serveWithRouteID(t, engine, "limited", "/api/data")
		if resp.StatusCode() != 200 {
			t.Fatalf("request %d must pass, got %d: %s", i+1, resp.StatusCode(), responseString(resp))
		}
	}
	resp := serveWithRouteID(t, engine, "limited", "/api/data")
	if resp.StatusCode() != 403 || responseString(resp) != "IP address banned" {
		t.Fatalf("usage-rule ban must answer 403 %q, got %d %q", "IP address banned", resp.StatusCode(), responseString(resp))
	}
}

// Global return_pattern rules with behavior_scan_response_body enabled and a
// bounded inspect budget: the adapter hands the handler's buffered response
// body (bounded by the inspect budget) to Engine.ProcessResponse, the rule
// trips, and the client is banned for subsequent requests. A pattern placed
// beyond the inspect budget never matches.
func TestReachabilityGlobalReturnPatternBodyScan(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.BehaviorScanResponseBody = true
		c.BehaviorMaxResponseBodyInspectBytes = 1024
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "leaked-secret", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	for i := 0; i < 2; i++ {
		resp := serveWithRouteID(t, engine, "", "/report", "report leaked-secret trailer")
		if resp.StatusCode() != 200 {
			t.Fatalf("request %d must pass, got %d", i+1, resp.StatusCode())
		}
	}
	resp := serveWithRouteID(t, engine, "", "/report", "report leaked-secret trailer")
	if resp.StatusCode() != 403 || responseString(resp) != "IP address banned" {
		t.Fatalf("return-pattern ban must answer 403 %q, got %d %q", "IP address banned", resp.StatusCode(), responseString(resp))
	}

	// Budget bound: the marker sits past the 1024-byte inspect budget, so
	// the rule can never match and the client is never banned.
	other := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.BehaviorScanResponseBody = true
		c.BehaviorMaxResponseBodyInspectBytes = 1024
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "beyond-the-budget", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	guard, err := New(other)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	app := fiberlib.New()
	app.Use(guard)
	app.All("/*", func(c fiberlib.Ctx) error {
		big := make([]byte, 2048)
		for i := range big {
			big[i] = 'a'
		}
		copy(big[1500:], "beyond-the-budget")
		return c.SendString(string(big))
	})
	for i := 0; i < 4; i++ {
		resp := runFiberApp(t, app, testRemoteAddr, newReq("GET", "/report", "", nil))
		if resp.StatusCode() != 200 {
			t.Fatalf("pattern beyond the budget must never trip, got %d on request %d", resp.StatusCode(), i+1)
		}
	}
}

// status: return patterns work with the scan flag off: the adapter still
// reports the response status to Engine.ProcessResponse.
func TestReachabilityStatusReturnPatternWithoutScan(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.BehaviorScanResponseBody = false
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "status:404", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	guard, err := New(engine)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	app := fiberlib.New()
	app.Use(guard)
	app.All("/*", func(c fiberlib.Ctx) error {
		c.Status(404)
		return c.SendString("missing")
	})
	for i := 0; i < 2; i++ {
		resp := runFiberApp(t, app, testRemoteAddr, newReq("GET", "/missing", "", nil))
		if resp.StatusCode() != 404 {
			t.Fatalf("request %d must answer 404, got %d", i+1, resp.StatusCode())
		}
	}
	if !engine.Ban.IsIPBanned("192.0.2.1") {
		t.Fatal("two 404s over threshold 1 must ban the client through the adapter")
	}
}

// Per-route detection exclusions (the #28 surface): the excluded query
// parameter no longer reaches detection on the configured route, while the
// same payload is blocked everywhere else with the reference 400.
func TestReachabilityPerRouteDetectionExclusions(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.Routes.Register("open", func(rc *guardcore.RouteConfig) {
		rc.ExcludedDetectionParams = map[string]bool{"q": true}
	})
	resp := serveWithRouteID(t, engine, "open", "/search?q=<script>alert(1)</script>")
	if resp.StatusCode() != 200 {
		t.Fatalf("excluded param must pass on the configured route, got %d: %s", resp.StatusCode(), responseString(resp))
	}
	resp = serveWithRouteID(t, engine, "", "/search?q=<script>alert(1)</script>")
	if resp.StatusCode() != 400 || responseString(resp) != "Suspicious activity detected" {
		t.Fatalf("the same payload must be blocked off-route with 400 %q, got %d %q",
			"Suspicious activity detected", resp.StatusCode(), responseString(resp))
	}
}

// Geo lifecycle: route country rules resolve through the configured
// GeoIPHandler, a blocked country answers the reference 403 "Forbidden", and
// the OnGeoEvent hook receives the country_blocked event with the reference
// fields.
func TestReachabilityGeoLifecycle(t *testing.T) {
	var events []guardcore.GeoEvent
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.GeoIPHandler = fakeCountryResolver{country: "CN"}
		c.OnGeoEvent = func(ev guardcore.GeoEvent) { events = append(events, ev) }
	})
	// Route-level country rules (the geo lifecycle's observable path for
	// country_blocked; the global country verdict blocks without emitting
	// the event in this port).
	engine.Routes.Register("geo", func(rc *guardcore.RouteConfig) {
		rc.BlockedCountries = []string{"CN"}
	})
	resp := serveWithRouteID(t, engine, "geo", "/download")
	if resp.StatusCode() != 403 || responseString(resp) != "Forbidden" {
		t.Fatalf("blocked country must answer 403 %q, got %d %q", "Forbidden", resp.StatusCode(), responseString(resp))
	}
	// The route country deny emits country_blocked followed by the
	// decorator_violation access-denied event, both with the reference
	// fields.
	if len(events) != 2 {
		t.Fatalf("OnGeoEvent must receive country_blocked and decorator_violation, got %+v", events)
	}
	blocked, violation := events[0], events[1]
	if blocked.EventType != guardcore.EventCountryBlocked || blocked.Country != "CN" ||
		blocked.RuleType != "country_blacklist" || blocked.ActionTaken != "request_blocked" {
		t.Fatalf("country_blocked event fields mismatch, got %+v", blocked)
	}
	if violation.EventType != guardcore.EventDecoratorViolation || violation.Metadata["decorator_type"] != "block_countries" {
		t.Fatalf("decorator_violation event fields mismatch, got %+v", violation)
	}
}

// IPInfo lifecycle validation: a max-age without a token fails config
// construction (the adapter cannot be handed such an engine), and a valid
// token with max-age 0 falls back to the reference default of 86400.
func TestReachabilityIPInfoLifecycleConfig(t *testing.T) {
	if _, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.IPInfoMaxAge = 3600
	}); err == nil || !strings.Contains(err.Error(), "ipinfo_token") {
		t.Fatalf("max-age without token must fail config construction, got %v", err)
	}
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.IPInfoToken = "token"
	})
	if err != nil {
		t.Fatalf("token-only config must validate: %v", err)
	}
	if cfg.IPInfoMaxAge != guardcore.DefaultIPInfoMaxAge {
		t.Fatalf("max-age default must be %d, got %d", guardcore.DefaultIPInfoMaxAge, cfg.IPInfoMaxAge)
	}
}

// CORS: pass-through responses carry the CORS headers merged over the
// security-header set, and preflights are short-circuited by the engine
// through the adapter.
func TestReachabilityCORS(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.EnableCORS = true
		c.CORSAllowOrigins = []string{"https://app.example"}
		c.CORSAllowMethods = []string{"GET", "POST"}
	})

	r := newReq("GET", "/api", "", map[string]string{"Origin": "https://app.example"})
	resp := runFiberAppWithGuard(t, guard, r)
	if resp.StatusCode() != 200 {
		t.Fatalf("pass-through must stay 200, got %d", resp.StatusCode())
	}
	if got := string(resp.Header.Peek("Access-Control-Allow-Origin")); got != "https://app.example" {
		t.Fatalf("pass-through must carry the CORS allow-origin header, got %q", got)
	}
	if len(resp.Header.Peek("X-Content-Type-Options")) == 0 {
		t.Fatal("CORS headers must be merged over the security-header set, not replace it")
	}

	preflight := newReq("OPTIONS", "/api", "", map[string]string{
		"Origin":                        "https://app.example",
		"Access-Control-Request-Method": "POST",
	})
	resp = runFiberAppWithGuard(t, guard, preflight)
	if resp.StatusCode() != 200 || responseString(resp) != "OK" {
		t.Fatalf("allowed preflight must short-circuit 200 OK, got %d %q", resp.StatusCode(), responseString(resp))
	}

	denied := newReq("OPTIONS", "/api", "", map[string]string{
		"Origin":                        "https://evil.example",
		"Access-Control-Request-Method": "POST",
	})
	resp = runFiberAppWithGuard(t, guard, denied)
	if resp.StatusCode() != 400 || !strings.HasPrefix(responseString(resp), "Disallowed CORS:") {
		t.Fatalf("disallowed preflight must answer 400 Disallowed CORS, got %d %q", resp.StatusCode(), responseString(resp))
	}
}

func runFiberAppWithGuard(t *testing.T, guard fiberlib.Handler, req *fasthttp.Request) *fasthttp.Response {
	t.Helper()
	app := fiberlib.New()
	app.Use(guard)
	app.All("/*", func(c fiberlib.Ctx) error {
		return c.SendString("ok")
	})
	return runFiberApp(t, app, testRemoteAddr, req)
}

// Custom error bodies compose with the detection verdict: the configured
// 400 body replaces the default while the status code and the security
// headers stay engine-owned.
func TestReachabilityCustomErrorResponses(t *testing.T) {
	guard, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomErrorResponses = map[int]string{400: "custom detection body"}
	})
	wantSecurityHeaders := engine.ResponseHeaders()
	r := newReq("GET", "/search?q=<script>alert(1)</script>", "", nil)
	resp, p := serve(t, guard, testRemoteAddr, r)
	if resp.StatusCode() != 400 || responseString(resp) != "custom detection body" {
		t.Fatalf("custom error body must be reachable, got %d %q", resp.StatusCode(), responseString(resp))
	}
	if p.called {
		t.Fatal("a blocked request must not reach the handler")
	}
	for name, value := range wantSecurityHeaders {
		if got := string(resp.Header.Peek(name)); got != value {
			t.Fatalf("blocked response must still carry security header %s = %q, got %q", name, value, got)
		}
	}
}
