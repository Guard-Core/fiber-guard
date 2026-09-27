package fiber

import (
	"bytes"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	fiberlib "github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const xssVector = "q=<script>alert(1)</script>"

type probe struct {
	called   bool
	headers  http.Header
	body     []byte
	method   string
	path     string
	rawQuery string
}

func newTestEngine(t *testing.T, mutate func(*guardcore.SecurityConfig)) *guardcore.Engine {
	t.Helper()
	cfg := guardcore.DefaultSecurityConfig()
	cfg.EnableRedis = false
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return engine
}

func newTestMiddleware(t *testing.T, mutate func(*guardcore.SecurityConfig), opts ...Option) (fiberlib.Handler, *guardcore.Engine) {
	t.Helper()
	engine := newTestEngine(t, mutate)
	guard, err := New(engine, opts...)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	return guard, engine
}

func tcpAddr(remoteAddr string) *net.TCPAddr {
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host, port = remoteAddr, "0"
	}
	p, _ := strconv.Atoi(port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
}

func newReq(method, target, body string, headers map[string]string) *fasthttp.Request {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(target)
	req.Header.SetMethod(method)
	if headers != nil {
		for name, value := range headers {
			req.Header.Add(name, value)
		}
	}
	if len(body) > 0 {
		req.SetBodyRaw([]byte(body))
	}
	return req
}

func runFiberApp(t *testing.T, app *fiberlib.App, remoteAddr string, req *fasthttp.Request) *fasthttp.Response {
	t.Helper()
	handler := app.Handler()
	fctx := &fasthttp.RequestCtx{}
	fctx.Init(req, tcpAddr(remoteAddr), nil)
	handler(fctx)
	return &fctx.Response
}

func serve(t *testing.T, guard fiberlib.Handler, remoteAddr string, req *fasthttp.Request, pres ...fiberlib.Handler) (*fasthttp.Response, *probe) {
	t.Helper()
	p := &probe{}
	app := fiberlib.New()
	for _, pre := range pres {
		app.Use(pre)
	}
	app.Use(guard)
	app.All("/*", func(c fiberlib.Ctx) error {
		p.called = true
		p.headers = http.Header(c.GetRespHeaders())
		p.body = bytes.Clone(c.Body())
		p.method = c.Method()
		p.path = c.Path()
		p.rawQuery = string(c.RequestCtx().URI().QueryString())
		return c.SendString("ok")
	})
	return runFiberApp(t, app, remoteAddr, req), p
}

func withCtx(t *testing.T, remoteAddr string, req *fasthttp.Request, run func(c fiberlib.Ctx)) *fasthttp.Response {
	t.Helper()
	app := fiberlib.New()
	app.All("/*", func(c fiberlib.Ctx) error {
		run(c)
		return c.SendString("ok")
	})
	return runFiberApp(t, app, remoteAddr, req)
}

func assertBlockedStatus(t *testing.T, resp *fasthttp.Response, wantStatus int) {
	t.Helper()
	if resp.StatusCode() != wantStatus {
		t.Fatalf("status mismatch, want %d got %d", wantStatus, resp.StatusCode())
	}
}

func assertBlockedResponse(t *testing.T, resp *fasthttp.Response, wantStatus int, wantBody string) {
	t.Helper()
	if resp.StatusCode() != wantStatus {
		t.Fatalf("status mismatch, want %d got %d", wantStatus, resp.StatusCode())
	}
	if string(resp.Body()) != wantBody {
		t.Fatalf("body mismatch, want %q got %q", wantBody, string(resp.Body()))
	}
}

func TestMiddlewareNilEngineRejected(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil engine must be rejected")
	}
}

func TestMiddlewareAllowsRequestUnmutated(t *testing.T) {
	guard, engine := newTestMiddleware(t, nil)
	req := newReq("GET", "/api/users?v=1", "", nil)
	resp, p := serve(t, guard, "192.0.2.44:51234", req)
	if resp.StatusCode() != 200 || !p.called {
		t.Fatalf("clean request must reach the handler, got %d called=%v", resp.StatusCode(), p.called)
	}
	if p.method != "GET" || p.path != "/api/users" || p.rawQuery != "v=1" {
		t.Fatalf("handler must see the original request, got %s %s?%s", p.method, p.path, p.rawQuery)
	}
	// fasthttp surfaces its default "Content-Type: text/plain; charset=utf-8"
	// on every response from the start of the handler chain (unlike net/http).
	// Beyond that server-owned default the handler sees exactly the engine's
	// security header set. fasthttp canonicalizes header names its own way
	// (X-XSS-Protection becomes X-Xss-Protection), so membership and value
	// checks must be case-insensitive.
	want := engine.ResponseHeaders()
	for name := range p.headers {
		if strings.EqualFold(name, "Content-Type") {
			continue
		}
		found := false
		for engineName := range want {
			if strings.EqualFold(name, engineName) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("adapter must add only security headers on pass, got %v", p.headers)
		}
	}
	for name, value := range want {
		if got := string(p.headers.Get(name)); !strings.EqualFold(string(got), value) {
			t.Fatalf("security header %s = %q, want %q", name, got, value)
		}
	}
}

// Security headers land on every pass-through response; disabling them
// restores the header-free pass (fasthttp's default Content-Type aside).
func TestMiddlewareAppliesSecurityHeadersOnPass(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.SecurityHeaders.Enabled = false
	})
	req := newReq("GET", "/api/users", "", nil)
	resp, p := serve(t, guard, "192.0.2.44:51234", req)
	if resp.StatusCode() != 200 || !p.called {
		t.Fatalf("clean request must pass, got %d called=%v", resp.StatusCode(), p.called)
	}
	for name := range p.headers {
		if !strings.EqualFold(name, "Content-Type") {
			t.Fatalf("disabled security headers must add nothing on pass, got %v", p.headers)
		}
	}
}

// Config overrides and custom headers flow through the adapter untouched.
func TestMiddlewareSecurityHeadersHonorsConfig(t *testing.T) {
	guard, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.SecurityHeaders.FrameOptions = "DENY"
		c.SecurityHeaders.Custom = map[string]string{"X-Request-Realm": "edge"}
	})
	want := engine.ResponseHeaders()
	req := newReq("GET", "/api", "", nil)
	resp, _ := serve(t, guard, "192.0.2.44:51234", req)
	if got := resp.Header.Peek("X-Frame-Options"); string(got) != "DENY" {
		t.Fatalf("override must reach the response, got X-Frame-Options %q", got)
	}
	if got := resp.Header.Peek("X-Request-Realm"); string(got) != "edge" {
		t.Fatalf("custom header must reach the response, got X-Request-Realm %q", got)
	}
	if len(want) == 0 {
		t.Fatal("engine must produce the header set")
	}
}

func TestMiddlewareBlocksBannedIPExactly(t *testing.T) {
	guard, engine := newTestMiddleware(t, nil)
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	req := newReq("GET", "/api", "", nil)
	resp, p := serve(t, guard, "203.0.113.7:4711", req)
	assertBlockedResponse(t, resp, 403, guardcore.IPBanBlockedMessage)
	if p.called {
		t.Fatal("blocked request must not reach the handler")
	}
	// The verdict carries no routing headers of its own beyond the engine's
	// security headers. fasthttp itself adds the default Content-Type when a
	// body is written; that is server behavior, not adapter translation.
	if location := string(resp.Header.Peek("Location")); location != "" {
		t.Fatalf("verdict must not inject routing headers, got Location %q", location)
	}
	for name, value := range engine.ResponseHeaders() {
		if got := string(resp.Header.Peek(name)); got != value {
			t.Fatalf("blocked response security header %s = %q, want %q", name, got, value)
		}
	}
}

func TestMiddlewareCustomErrorMessage(t *testing.T) {
	guard, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomErrorResponses[403] = "denied by policy"
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	req := newReq("GET", "/api", "", nil)
	resp, _ := serve(t, guard, "203.0.113.7:4711", req)
	assertBlockedResponse(t, resp, 403, "denied by policy")
}

func TestMiddlewareTranslatesRedirectVerdictHeaders(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.EnforceHTTPS = true
	})
	req := newReq("GET", "/api", "", nil)
	req.Header.SetHost("example.com")
	resp, p := serve(t, guard, "192.0.2.44:51234", req)
	if resp.StatusCode() != 301 || p.called {
		t.Fatalf("http request must redirect with 301, got %d called=%v", resp.StatusCode(), p.called)
	}
	if location := string(resp.Header.Peek("Location")); location != "https://example.com/api" {
		t.Fatalf("Location header must come from the verdict, got %q", location)
	}
}

func TestMiddlewarePOSTBodyScannedAndAvailable(t *testing.T) {
	var firstRead, secondRead []byte
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			firstRead, _ = req.Body()
			secondRead, _ = req.Body()
			if bytes.Contains(firstRead, []byte("evil")) {
				return &guardcore.Response{StatusCode: 403, Body: []byte("malicious body")}
			}
			return nil
		}
	})
	benign := newReq("POST", "/submit", "hello world", nil)
	resp, p := serve(t, guard, "192.0.2.44:51234", benign)
	if resp.StatusCode() != 200 || !p.called || string(p.body) != "hello world" {
		t.Fatalf("benign body must pass and stay readable for the handler, got %d handler-body=%q", resp.StatusCode(), p.body)
	}
	if !bytes.Equal(firstRead, secondRead) {
		t.Fatalf("Body() must be idempotent, got %q then %q", firstRead, secondRead)
	}
	evil := newReq("POST", "/submit", "evil payload", nil)
	resp, p = serve(t, guard, "192.0.2.44:51234", evil)
	assertBlockedResponse(t, resp, 403, "malicious body")
	if p.called {
		t.Fatal("body content must block")
	}
}

func TestMiddlewareBoundedBodyOnlyScansPrefix(t *testing.T) {
	var seenLen int
	var seen []byte
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			seen, _ = req.Body()
			seenLen = len(seen)
			if bytes.Contains(seen, []byte("evil")) {
				return &guardcore.Response{StatusCode: 403, Body: []byte("malicious body")}
			}
			return nil
		}
	}, WithMaxBodyBytes(16))
	payload := strings.Repeat("x", 20) + "evil" + strings.Repeat("y", 40)
	oversize := newReq("POST", "/submit", payload, nil)
	resp, p := serve(t, guard, "192.0.2.44:51234", oversize)
	if resp.StatusCode() != 200 || !p.called {
		t.Fatalf("marker beyond the bounded prefix must pass, got %d called=%v", resp.StatusCode(), p.called)
	}
	if seenLen != 16 {
		t.Fatalf("engine must only see the bounded prefix, got %d bytes", seenLen)
	}
	if string(p.body) != payload {
		t.Fatal("handler must still receive the full body")
	}
	inline := newReq("POST", "/submit", "evil"+strings.Repeat("x", 60), nil)
	resp, p = serve(t, guard, "192.0.2.44:51234", inline)
	assertBlockedResponse(t, resp, 403, "malicious body")
	if p.called {
		t.Fatal("marker inside the prefix must block")
	}
}

func TestRequestShimBoundedPrefixAndHandlerReadsFullBody(t *testing.T) {
	body := strings.Repeat("A", 12) + "TAIL"
	var replayed []byte
	var handlerErr error
	req := newReq("POST", "/submit", body, nil)
	withCtx(t, "192.0.2.44:51234", req, func(c fiberlib.Ctx) {
		shim := newRequestShim(c, 8)
		prefix, err := shim.ReadBodyPrefix(4)
		if err != nil || string(prefix) != "AAAA" {
			handlerErr = err
			return
		}
		if extended, _ := shim.ReadBodyPrefix(8); string(extended) != strings.Repeat("A", 8) {
			handlerErr = err
			return
		}
		if clamped, _ := shim.ReadBodyPrefix(100); len(clamped) != 8 {
			handlerErr = err
			return
		}
		if negative, _ := shim.ReadBodyPrefix(-5); len(negative) != 8 {
			handlerErr = err
			return
		}
		cached, err := shim.Body()
		if err != nil || len(cached) != 8 {
			handlerErr = err
			return
		}
		replayed = bytes.Clone(c.Body())
	})
	if handlerErr != nil {
		t.Fatalf("shim prefix reads: %v", handlerErr)
	}
	if string(replayed) != body {
		t.Fatalf("handler must still read the full body through fiber, got %q", replayed)
	}
}

func TestRequestShimConstructionLeavesBodyIntact(t *testing.T) {
	body := "stream-me"
	var got []byte
	req := newReq("POST", "/submit", body, nil)
	withCtx(t, "192.0.2.44:51234", req, func(c fiberlib.Ctx) {
		_ = newRequestShim(c, 64)
		got = bytes.Clone(c.Body())
	})
	if string(got) != body {
		t.Fatalf("un-read body must stay untouched for the handler, got %q", got)
	}
}

func TestRequestShimFiberContextConversion(t *testing.T) {
	req := newReq("post", "/api/items?tag=first&tag=second&page=2", "payload", nil)
	req.Header.Add("X-Forwarded-For", "203.0.113.9")
	req.Header.Add("X-Forwarded-For", "198.51.100.4")
	req.Header.SetHost("example.com:8080")
	withCtx(t, "192.0.2.44:51234", req, func(c fiberlib.Ctx) {
		shim := newRequestShim(c, DefaultMaxBodyBytes)
		if shim.URLPath() != "/api/items" {
			t.Fatalf("path conversion mismatch, got %q", shim.URLPath())
		}
		if shim.URLScheme() != "http" {
			t.Fatalf("scheme conversion mismatch, got %q", shim.URLScheme())
		}
		if full := shim.URLFull(); full != "http://example.com:8080/api/items?tag=first&tag=second&page=2" {
			t.Fatalf("full URL conversion mismatch, got %q", full)
		}
		if replaced := shim.URLReplaceScheme("https"); replaced != "https://example.com:8080/api/items?tag=first&tag=second&page=2" {
			t.Fatalf("scheme replacement mismatch, got %q", replaced)
		}
		if shim.Method() != "POST" {
			t.Fatalf("method must be uppercased, got %q", shim.Method())
		}
		if host := shim.ClientHost(); host != "192.0.2.44" {
			t.Fatalf("client host must come from the fasthttp peer address, got %q", host)
		}
		headers := shim.Headers()
		if value, ok := headers.Get("X-Forwarded-For"); !ok || value != "203.0.113.9" {
			t.Fatalf("only the first header value must be adapted, got %q ok=%v", value, ok)
		}
		if host, ok := headers.Get("Host"); !ok || host != "example.com:8080" {
			t.Fatalf("Host header must be adapted from the request, got %q ok=%v", host, ok)
		}
		params := shim.QueryParams()
		if params["tag"] != "first" || params["page"] != "2" || len(params) != 2 {
			t.Fatalf("query params must take the first value per key, got %v", params)
		}
		if shim.State().GuardRouteID != "" {
			t.Fatalf("route id must stay empty without the context key, got %q", shim.State().GuardRouteID)
		}
		c.SetContext(WithRouteID(c.Context(), "open"))
		if id := newRequestShim(c, DefaultMaxBodyBytes).State().GuardRouteID; id != "open" {
			t.Fatalf("route id must be copied from the fiber user context, got %q", id)
		}
	})
}

func TestRequestShimIPv6PeerIP(t *testing.T) {
	var got string
	req := newReq("GET", "/api", "", nil)
	withCtx(t, "192.0.2.44:51234", req, func(c fiberlib.Ctx) {
		got = newRequestShim(c, DefaultMaxBodyBytes).ClientHost()
	})
	if got != "192.0.2.44" {
		t.Fatalf("sanity peer mismatch, got %q", got)
	}
	req6 := newReq("GET", "/api", "", nil)
	withCtx(t, "[2001:db8::1]:4711", req6, func(c fiberlib.Ctx) {
		got = newRequestShim(c, DefaultMaxBodyBytes).ClientHost()
	})
	if got != "2001:db8::1" {
		t.Fatalf("ipv6 peer must pass through as the engine client host, got %q", got)
	}
}

func TestMiddlewareRouteBypassAll(t *testing.T) {
	guard, engine := newTestMiddleware(t, nil)
	engine.Routes.Register("open", func(rc *guardcore.RouteConfig) {
		rc.BypassedChecks = []string{"all"}
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	pre := func(c fiberlib.Ctx) error {
		c.SetContext(WithRouteID(c.Context(), "open"))
		return c.Next()
	}
	req := newReq("GET", "/api", "", nil)
	resp, p := serve(t, guard, "203.0.113.7:4711", req, pre)
	if resp.StatusCode() != 200 || !p.called {
		t.Fatalf("bypass-all route must reach the handler even for banned IPs, got %d called=%v", resp.StatusCode(), p.called)
	}
	plain := newReq("GET", "/api", "", nil)
	resp, p = serve(t, guard, "203.0.113.7:4711", plain)
	assertBlockedResponse(t, resp, 403, guardcore.IPBanBlockedMessage)
	if p.called {
		t.Fatal("without the route id the ban must hold")
	}
}

func TestMiddlewareExclusionScoping(t *testing.T) {
	guard, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.ExcludePaths = []string{"/public"}
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	banned := newReq("GET", "/public/data", "", nil)
	resp, p := serve(t, guard, "203.0.113.7:4711", banned)
	assertBlockedResponse(t, resp, 403, guardcore.IPBanBlockedMessage)
	if p.called {
		t.Fatal("ip ban stays enforced on excluded paths")
	}
	excluded := newReq("GET", "/public?"+xssVector, "", nil)
	resp, p = serve(t, guard, "192.0.2.44:51234", excluded)
	if resp.StatusCode() != 200 || !p.called {
		t.Fatalf("suspicious detection must be skipped in exclusion scope, got %d called=%v", resp.StatusCode(), p.called)
	}
	scoped := newReq("GET", "/search?"+xssVector, "", nil)
	resp, p = serve(t, guard, "192.0.2.44:51234", scoped)
	assertBlockedStatus(t, resp, 400)
	if p.called {
		t.Fatal("same vector outside exclusions must be blocked")
	}
}

func TestMiddlewarePassiveModePassesThrough(t *testing.T) {
	var hookPayloads []map[string]any
	guard, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.PassiveMode = true
		c.OnBlock = func(req guardcore.Request, payload map[string]any) {
			hookPayloads = append(hookPayloads, payload)
		}
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	banned := newReq("GET", "/api", "", nil)
	resp, p := serve(t, guard, "203.0.113.7:4711", banned)
	if resp.StatusCode() != 200 || !p.called {
		t.Fatalf("passive mode must pass through even for banned IPs, got %d called=%v", resp.StatusCode(), p.called)
	}
	vector := newReq("GET", "/search?"+xssVector, "", nil)
	resp, p = serve(t, guard, "192.0.2.44:51234", vector)
	if resp.StatusCode() != 200 || !p.called {
		t.Fatalf("passive mode must pass through detection, got %d called=%v", resp.StatusCode(), p.called)
	}
	if len(hookPayloads) != 2 {
		t.Fatalf("passive mode must fire the on_block hook per corpus: ip_security for the banned pass-through, then suspicious_activity for detection, got %v", hookPayloads)
	}
	if hookPayloads[0]["check_name"] != "ip_security" || hookPayloads[0]["passive_mode"] != true {
		t.Fatalf("banned-IP pass-through must fire the ip_security hook with passive_mode true, got %v", hookPayloads[0])
	}
	if hookPayloads[1]["check_name"] != "suspicious_activity" || hookPayloads[1]["passive_mode"] != true {
		t.Fatalf("detection pass-through must fire the suspicious_activity hook with passive_mode true, got %v", hookPayloads[1])
	}
}

func TestMiddlewareWhitelistHonored(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.Whitelist = []string{"203.0.113.7"}
	})
	allowed := newReq("GET", "/search?"+xssVector, "", nil)
	resp, p := serve(t, guard, "203.0.113.7:4711", allowed)
	if resp.StatusCode() != 200 || !p.called {
		t.Fatalf("whitelisted IP must pass, got %d called=%v", resp.StatusCode(), p.called)
	}
	other := newReq("GET", "/search?"+xssVector, "", nil)
	resp, p = serve(t, guard, "203.0.113.99:4711", other)
	assertBlockedStatus(t, resp, 403)
	if p.called {
		t.Fatal("non-whitelisted IP must be denied by ip security")
	}
}

func TestMiddlewareCustomCheckPanicFailsClosed(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			panic("validator exploded")
		}
	})
	req := newReq("GET", "/api", "", nil)
	resp, p := serve(t, guard, "192.0.2.44:51234", req)
	assertBlockedResponse(t, resp, 500, "Security check failed")
	if p.called {
		t.Fatal("fail-secure must translate to 500 without reaching the handler")
	}
}

func TestMiddlewareFailClosedHonorsCustomMessage(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomErrorResponses[500] = "upstream refused"
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			panic("validator exploded")
		}
	})
	req := newReq("GET", "/api", "", nil)
	resp, p := serve(t, guard, "192.0.2.44:51234", req)
	assertBlockedResponse(t, resp, 500, "upstream refused")
	if p.called {
		t.Fatal("fail-closed response must not reach the handler")
	}
}

func TestMiddlewareWithLoggerReceivesFailClosed(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	m := &middleware{engine: &guardcore.Engine{}, maxBytes: DefaultMaxBodyBytes, logger: logger}
	req := newReq("GET", "/api", "", nil)
	resp, p := serve(t, m.wrap, "192.0.2.44:51234", req)
	assertBlockedResponse(t, resp, 500, failClosedMessage)
	if p.called {
		t.Fatal("malfunctioning engine must fail closed")
	}
	if !strings.Contains(buf.String(), "engine malfunction, failing closed") || !strings.Contains(buf.String(), "engine panic:") {
		t.Fatalf("custom logger must receive the malfunction detail, got %q", buf.String())
	}
}

func TestMiddlewareInvalidOptionsIgnored(t *testing.T) {
	engine := newTestEngine(t, nil)
	guard, err := New(engine, WithMaxBodyBytes(-1), WithLogger(nil))
	if err != nil {
		t.Fatalf("invalid option values must be ignored, got %v", err)
	}
	req := newReq("GET", "/api", "", nil)
	resp, p := serve(t, guard, "192.0.2.44:51234", req)
	if resp.StatusCode() != 200 || !p.called {
		t.Fatalf("middleware with defaults must pass clean traffic, got %d called=%v", resp.StatusCode(), p.called)
	}
}

func TestMiddlewareRouteIDViaRequestPathMapping(t *testing.T) {
	// Regression: Fiber v3 leaves c.Route() pointing at a use-middleware's
	// own route entry ("/"), so a route-ID mapper keyed on c.FullPath()
	// never matches and route-scoped engine config silently never applies.
	// The mapper must match the concrete request path (c.Path()) for the
	// engine's route_config check to fire, including on group-registered
	// routes like the advanced example's /admin group.
	guard, engine := newTestMiddleware(t, nil)
	engine.Routes.Register("admin", func(rc *guardcore.RouteConfig) {
		rc.RequiredHeaders = guardcore.RequiredHeaders{
			{Name: "X-Admin-Token", Value: "secret"},
		}
	})

	routeIDs := map[string]string{"/admin/banned": "admin"}
	app := fiberlib.New()
	app.Use(func(c fiberlib.Ctx) error {
		if routeID, ok := routeIDs[c.Path()]; ok {
			c.SetContext(WithRouteID(c.Context(), routeID))
		}
		return c.Next()
	})
	app.Use(guard)
	admin := app.Group("/admin")
	admin.Get("/banned", func(c fiberlib.Ctx) error {
		return c.SendString("ok")
	})

	missing := runFiberApp(t, app, "192.0.2.44:51234", newReq("GET", "/admin/banned", "", nil))
	if missing.StatusCode() != 400 {
		t.Fatalf("missing admin token must be rejected with 400 by the engine's required-header guard, got %d", missing.StatusCode())
	}
	if !strings.Contains(string(missing.Body()), "Missing required header: X-Admin-Token") {
		t.Fatalf("missing-token body must name the header, got %q", string(missing.Body()))
	}

	authed := newReq("GET", "/admin/banned", "", map[string]string{"X-Admin-Token": "secret"})
	ok := runFiberApp(t, app, "192.0.2.44:51234", authed)
	if ok.StatusCode() != 200 {
		t.Fatalf("valid admin token must reach the handler, got %d", ok.StatusCode())
	}

	unmapped := runFiberApp(t, app, "192.0.2.44:51234", newReq("GET", "/admin/other", "", nil))
	if unmapped.StatusCode() != 404 {
		t.Fatalf("unregistered admin subroute must 404 (no handler), got %d", unmapped.StatusCode())
	}
}
