package fiber

import (
	"testing"

	fiberlib "github.com/gofiber/fiber/v3"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

func wsTestEngine(t *testing.T, mutate func(*guardcore.SecurityConfig)) *guardcore.Engine {
	t.Helper()
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.EnableRedis = false
		if mutate != nil {
			mutate(c)
		}
	})
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestGuardWebSocketAllowsCleanUpgrade(t *testing.T) {
	engine := wsTestEngine(t, nil)
	withCtx(t, "203.0.113.9:1234", newReq("GET", "/ws", "", map[string]string{"Upgrade": "websocket"}), func(c fiberlib.Ctx) {
		if reason := GuardWebSocket(engine, c); reason != nil {
			t.Fatalf("clean upgrade must pass, got %+v", reason)
		}
		if status := WebSocketHTTPStatus(nil); status != 200 {
			t.Fatalf("nil reason must map to 200, got %d", status)
		}
	})
}

func TestGuardWebSocketBannedIPCloses(t *testing.T) {
	engine := wsTestEngine(t, nil)
	if _, err := engine.Ban.Ban("203.0.113.9", 60, "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	withCtx(t, "203.0.113.9:1234", newReq("GET", "/ws", "", nil), func(c fiberlib.Ctx) {
		reason := GuardWebSocket(engine, c)
		if reason == nil || *reason != guardcore.WSCloseIPBanned {
			t.Fatalf("banned IP must close with the banned reason, got %+v", reason)
		}
		if status := WebSocketHTTPStatus(reason); status != 403 {
			t.Fatalf("policy violation must map to 403, got %d", status)
		}
	})
}

func TestGuardWebSocketSuspiciousHandshakeCloses(t *testing.T) {
	engine := wsTestEngine(t, nil)
	withCtx(t, "203.0.113.9:1234", newReq("GET", "/ws/search?q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--", "", nil), func(c fiberlib.Ctx) {
		reason := GuardWebSocket(engine, c)
		if reason == nil || *reason != guardcore.WSCloseSuspiciousActivity {
			t.Fatalf("suspicious handshake must close with the suspicious reason, got %+v", reason)
		}
		if status := WebSocketHTTPStatus(reason); status != 403 {
			t.Fatalf("suspicious must map to 403, got %d", status)
		}
	})
}

func TestGuardWebSocketNilEngineFailsClosed(t *testing.T) {
	withCtx(t, "203.0.113.9:1234", newReq("GET", "/ws", "", nil), func(c fiberlib.Ctx) {
		reason := GuardWebSocket(nil, c)
		if reason == nil || *reason != guardcore.WSCloseSecurityCheckFailed {
			t.Fatalf("nil engine must fail closed, got %+v", reason)
		}
		if status := WebSocketHTTPStatus(reason); status != 503 {
			t.Fatalf("security-check-failed must map to 503, got %d", status)
		}
	})
}

func TestWSRequestShimContract(t *testing.T) {
	withCtx(t, "203.0.113.9:1234", newReq("GET", "http://example.com/ws?a=1&a=2", "", map[string]string{"X-Custom": "one"}), func(c fiberlib.Ctx) {
		c.RequestCtx().Request.Header.Add("X-Custom", "two")
		shim := newWSRequestShim(c)
		if shim.Method() != "WEBSOCKET" {
			t.Fatalf("the ws shim must report the WEBSOCKET method, got %q", shim.Method())
		}
		if body, err := shim.Body(); err != nil || body != nil {
			t.Fatalf("the ws shim must carry an empty body, got (%v, %v)", body, err)
		}
		if joined, _ := shim.Headers().Get("X-Custom"); joined != "one, two" {
			t.Fatalf("repeated headers must join with a comma, got %q", joined)
		}
		if shim.QueryParams()["a"] != "1" {
			t.Fatalf("query params must keep the first value, got %q", shim.QueryParams()["a"])
		}
		if shim.ClientHost() != "203.0.113.9" {
			t.Fatalf("client host must come from the remote address, got %q", shim.ClientHost())
		}
		if shim.State() == nil {
			t.Fatal("the ws shim must expose a request state")
		}
		if shim.URLScheme() != "http" {
			t.Fatalf("a plaintext request must resolve http, got %q", shim.URLScheme())
		}
		if full := shim.URLFull(); full != "http://example.com/ws?a=1&a=2" {
			t.Fatalf("the ws shim must build the full URL, got %q", full)
		}
		if replaced := shim.URLReplaceScheme("wss"); replaced != "wss://example.com/ws?a=1&a=2" {
			t.Fatalf("scheme replacement must swap the scheme, got %q", replaced)
		}
		if same := shim.URLReplaceScheme(""); same != shim.URLFull() {
			t.Fatalf("empty scheme replacement must keep the URL, got %q", same)
		}
	})
	// A nil remote address resolves to an empty client host.
	withCtx(t, "", newReq("GET", "/ws", "", nil), func(c fiberlib.Ctx) {
		shim := newWSRequestShim(c)
		if shim.ClientHost() != "" {
			t.Fatalf("a nil remote address must resolve to an empty host, got %q", shim.ClientHost())
		}
	})
}

func TestWSRequestShimTLSScheme(t *testing.T) {
	withCtx(t, "203.0.113.9:1234", newReq("GET", "http://example.com/ws", "", nil), func(c fiberlib.Ctx) {
		c.RequestCtx().Init2(fakeTLSConn{}, nil, true)
		shim := newWSRequestShim(c)
		if shim.URLScheme() != "https" {
			t.Fatalf("a TLS request must resolve https, got %q", shim.URLScheme())
		}
		if full := shim.URLFull(); full != "https://example.com/ws" {
			t.Fatalf("the ws shim must build the TLS full URL, got %q", full)
		}
	})
}
