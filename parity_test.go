package fiber

// Parity tests against the reference adapter (fastapi-guard): the response
// pass runs the custom response modifier last, and the request metrics and
// return rules see the real response status.

import (
	"errors"
	"testing"

	fiberlib "github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

func serveWith(t *testing.T, engine *guardcore.Engine, path string, handler fiberlib.Handler, req *fasthttp.Request) *fasthttp.Response {
	t.Helper()
	guard, err := New(engine)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	app := fiberlib.New()
	app.Use(guard)
	app.All(path, handler)
	return runFiberApp(t, app, testRemoteAddr, req)
}

func TestParityModifierRewritesPassThroughResponse(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response {
			resp.SetHeader("X-Modified", "yes")
			delete(resp.Headers, "X-Frame-Options")
			resp.Headers["X-Content-Type-Options"] = "changed"
			resp.Body = append([]byte("modified:"), resp.Body...)
			return resp
		}
	})
	resp := serveWith(t, engine, "/*", func(c fiberlib.Ctx) error {
		c.Response().Header.Add("Set-Cookie", "a=1")
		c.Response().Header.Add("Set-Cookie", "b=2")
		return c.Status(fiberlib.StatusCreated).SendString("hello")
	}, newReq("GET", "/api", "", nil))
	if resp.StatusCode() != fiberlib.StatusCreated {
		t.Fatalf("modifier must keep the handler status, got %d", resp.StatusCode())
	}
	if string(resp.Body()) != "modified:hello" {
		t.Fatalf("modifier must rewrite the pass-through body, got %q", resp.Body())
	}
	if string(resp.Header.Peek("X-Modified")) != "yes" {
		t.Fatalf("modifier header missing: %s", resp.Header.String())
	}
	if len(resp.Header.Peek("X-Frame-Options")) != 0 {
		t.Fatalf("modifier must be able to drop a security header: %s", resp.Header.String())
	}
	if string(resp.Header.Peek("X-Content-Type-Options")) != "changed" {
		t.Fatalf("modifier must be able to change a header: %s", resp.Header.String())
	}
	cookies := 0
	resp.Header.All()(func(key, _ []byte) bool {
		if string(key) == "Set-Cookie" {
			cookies++
		}
		return true
	})
	if cookies != 2 {
		t.Fatalf("untouched multi-value headers must survive, got %d", cookies)
	}
}

func TestParityModifierRunsAfterCORSAndCORSIsReapplied(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.EnableCORS = true
		c.CORSAllowOrigins = []string{"https://app.example"}
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response {
			sawCORS := resp.Headers["Access-Control-Allow-Origin"] == "https://app.example"
			delete(resp.Headers, "Access-Control-Allow-Origin")
			if sawCORS {
				resp.SetHeader("X-Saw-CORS", "yes")
			}
			return resp
		}
	})
	resp := serveWith(t, engine, "/*", func(c fiberlib.Ctx) error { return c.SendString("ok") },
		newReq("GET", "/api", "", map[string]string{"Origin": "https://app.example"}))
	if string(resp.Header.Peek("X-Saw-CORS")) != "yes" {
		t.Fatalf("the modifier must see the CORS headers: %s", resp.Header.String())
	}
	if string(resp.Header.Peek("Access-Control-Allow-Origin")) != "https://app.example" {
		t.Fatalf("CORS is injected after the modifier in the reference dispatch: %s", resp.Header.String())
	}
}

func TestParityModifierAppliesToGuardBlockedResponse(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response {
			resp.SetHeader("X-Modified", "yes")
			return resp
		}
	})
	resp := serveWith(t, engine, "/*", func(c fiberlib.Ctx) error { return c.SendString("ok") },
		newReq("GET", "/api?"+xssVector, "", nil))
	if resp.StatusCode() != 400 || string(resp.Header.Peek("X-Modified")) != "yes" {
		t.Fatalf("guard responses carry the modifier, got %d %s", resp.StatusCode(), resp.Header.String())
	}
}

func TestParityModifierStatusAndBodyFeedReturnRules(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.BehaviorScanResponseBody = true
		c.BehaviorMaxResponseBodyInspectBytes = 1024
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response { return resp }
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "secret", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	for i := 0; i < 2; i++ {
		resp := serveWith(t, engine, "/*", func(c fiberlib.Ctx) error { return c.SendString("a secret leaked here") },
			newReq("GET", "/report", "", nil))
		if resp.StatusCode() != 200 || string(resp.Body()) != "a secret leaked here" {
			t.Fatalf("modified response must reach the client intact, got %d %q", resp.StatusCode(), resp.Body())
		}
	}
	if !engine.Ban.IsIPBanned("192.0.2.1") {
		t.Fatal("the body of the response must reach the return rules")
	}
}

// A handler error is turned into a response by Fiber's ErrorHandler, which
// only runs after the middleware chain returns: c.Response().StatusCode()
// would still be the unwritten default, and the engine would record a 200.
func TestParityHandlerErrorStatusReachesEngine(t *testing.T) {
	for name, handler := range map[string]fiberlib.Handler{
		"fiber error": func(c fiberlib.Ctx) error { return fiberlib.NewError(fiberlib.StatusInternalServerError, "boom") },
		"plain error": func(c fiberlib.Ctx) error { return errors.New("boom") },
		"explicit":    func(c fiberlib.Ctx) error { return c.SendStatus(fiberlib.StatusInternalServerError) },
	} {
		t.Run(name, func(t *testing.T) {
			engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
				c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
					{RuleType: "return_pattern", Pattern: "status:500", Threshold: 1, Window: 60, Action: "ban"},
				}
			})
			for i := 0; i < 2; i++ {
				resp := serveWith(t, engine, "/*", handler, newReq("GET", "/boom", "", nil))
				if resp.StatusCode() != 500 {
					t.Fatalf("handler status must reach the client, got %d", resp.StatusCode())
				}
			}
			if !engine.Ban.IsIPBanned("192.0.2.1") {
				t.Fatal("a 500 must be reported to the engine as 500")
			}
		})
	}
}

func TestParityUnroutedRequestReportsNotFound(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "status:404", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	for i := 0; i < 2; i++ {
		resp := serveWith(t, engine, "/known", func(c fiberlib.Ctx) error { return c.SendString("ok") },
			newReq("GET", "/nope", "", nil))
		if resp.StatusCode() != 404 {
			t.Fatalf("an unrouted request answers 404, got %d", resp.StatusCode())
		}
	}
	if !engine.Ban.IsIPBanned("192.0.2.1") {
		t.Fatal("a 404 from the router must be reported to the engine as 404")
	}
}

func TestParityHandlerErrorWithModifierSeesErrorStatus(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response {
			if resp.StatusCode == fiberlib.StatusTeapot {
				resp.SetHeader("X-Seen-Teapot", "yes")
			}
			return resp
		}
	})
	resp := serveWith(t, engine, "/*", func(c fiberlib.Ctx) error { return fiberlib.NewError(fiberlib.StatusTeapot, "short") },
		newReq("GET", "/tea", "", nil))
	if resp.StatusCode() != fiberlib.StatusTeapot || string(resp.Header.Peek("X-Seen-Teapot")) != "yes" {
		t.Fatalf("the modifier must see the error status, got %d %s", resp.StatusCode(), resp.Header.String())
	}
}

func TestParityErrorHandlerFailureFallsBackTo500(t *testing.T) {
	engine := newTestEngine(t, nil)
	guard, err := New(engine)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	app := fiberlib.New(fiberlib.Config{ErrorHandler: func(c fiberlib.Ctx, err error) error {
		return errors.New("error handler failed")
	}})
	app.Use(guard)
	app.All("/*", func(c fiberlib.Ctx) error { return errors.New("boom") })
	resp := runFiberApp(t, app, testRemoteAddr, newReq("GET", "/api", "", nil))
	if resp.StatusCode() != 500 {
		t.Fatalf("a failing error handler must still answer 500, got %d", resp.StatusCode())
	}
}

// The engine's built-in default header exclusions (DefaultExcludedHeaders)
// keep address headers out of ssrf detection, so the examples and docs need
// no manual ExcludedDetectionHeaders workaround.
func TestParityAddressHeadersNeedNoManualExclusion(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) { c.EnablePenetrationDetection = true })
	resp := serveWith(t, engine, "/*", func(c fiberlib.Ctx) error { return c.SendString("ok") },
		newReq("GET", "/api", "", map[string]string{"Host": "169.254.169.254", "X-Forwarded-For": "10.0.0.1", "Origin": "http://localhost"}))
	if resp.StatusCode() != 200 {
		t.Fatalf("address headers must not be flagged by default, got %d %q", resp.StatusCode(), resp.Body())
	}
}
