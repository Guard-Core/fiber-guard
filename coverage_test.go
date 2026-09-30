package fiber

// Coverage tests: pin the remaining branch behavior of the adapter
// surface: option plumbing, TLS detection, method and peer-address edge
// conversions, and the default body budget.

import (
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"strings"
	"testing"

	fiberlib "github.com/gofiber/fiber/v3"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// WithLogger must install the provided logger: the fail-closed path then
// reports the engine malfunction through it instead of the default logger.
func TestWithLoggerInstallsProvidedLogger(t *testing.T) {
	var buf bytes.Buffer
	guard, err := New(&guardcore.Engine{}, WithLogger(log.New(&buf, "", 0)))
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	req := newReq("GET", "/api", "", nil)
	resp, p := serve(t, guard, "192.0.2.44:51234", req)
	if resp.StatusCode() != 500 || p.called {
		t.Fatalf("malfunctioning engine must fail closed, got %d called=%v", resp.StatusCode(), p.called)
	}
	if !strings.Contains(buf.String(), "engine malfunction, failing closed") {
		t.Fatalf("the provided logger must receive the malfunction report, got %q", buf.String())
	}
}

// fakeTLSConn satisfies fasthttp's tlsConn detection interface so the
// shim's scheme conversion can be observed without a real TLS handshake.
type fakeTLSConn struct{ net.Conn }

func (fakeTLSConn) Handshake() error                     { return nil }
func (fakeTLSConn) ConnectionState() tls.ConnectionState { return tls.ConnectionState{} }

// emptyMethodCtx forces the defensive empty-method branch that fasthttp
// itself can never produce (fasthttp always defaults to GET).
type emptyMethodCtx struct{ fiberlib.Ctx }

func (emptyMethodCtx) Method(...string) string { return "" }

// Request-shim conversions on the edges: TLS requests resolve https, the
// empty method defaults to GET, URLs without a query stay clean, empty
// scheme replacement is a no-op, an unparseable peer address yields an
// empty client host, and the body budget falls back to the default.
func TestRequestShimEdgeConversions(t *testing.T) {
	req := newReq("GET", "/api", "", nil)
	req.SetHost("example.com")
	withCtx(t, "192.0.2.44:51234", req, func(c fiberlib.Ctx) {
		shim := newRequestShim(c, DefaultMaxBodyBytes)
		if full := shim.URLFull(); full != "http://example.com/api" {
			t.Fatalf("URL without a query must have no question mark, got %q", full)
		}
		queried := newReq("GET", "/api?tag=first&page=2", "", nil)
		queried.SetHost("example.com")
		withCtx(t, "192.0.2.44:51234", queried, func(qc fiberlib.Ctx) {
			if full := newRequestShim(qc, DefaultMaxBodyBytes).URLFull(); full != "http://example.com/api?tag=first&page=2" {
				t.Fatalf("URL with a query must carry it verbatim, got %q", full)
			}
		})
		if replaced := shim.URLReplaceScheme(""); replaced != "http://example.com/api" {
			t.Fatalf("empty scheme replacement must return the full URL untouched, got %q", replaced)
		}
		if host := shim.ClientHost(); host != "192.0.2.44" {
			t.Fatalf("client host must come from the fasthttp peer address, got %q", host)
		}
		if shim.Method() != "GET" {
			t.Fatalf("GET must pass through uppercased, got %q", shim.Method())
		}
		// TLS: fasthttp derives the scheme from the connection, so the
		// detection seam (a tlsConn) is attached to the request context.
		c.RequestCtx().Init2(fakeTLSConn{}, nil, true)
		if shim.URLScheme() != "https" {
			t.Fatalf("TLS connection must resolve scheme https, got %q", shim.URLScheme())
		}
		emptyShim := newRequestShim(emptyMethodCtx{c}, DefaultMaxBodyBytes)
		if emptyShim.Method() != "GET" {
			t.Fatalf("empty method must default to GET, got %q", emptyShim.Method())
		}
		nonPositive := newRequestShim(c, 0)
		if nonPositive.maxBytes != DefaultMaxBodyBytes {
			t.Fatalf("non-positive body budget must fall back to the default, got %d", nonPositive.maxBytes)
		}
	})
	portless := newReq("GET", "/api", "", nil)
	portless.SetHost("example.com")
	withCtx(t, "not-an-ip", portless, func(c fiberlib.Ctx) {
		shim := newRequestShim(c, DefaultMaxBodyBytes)
		if host := shim.ClientHost(); host != "" {
			t.Fatalf("unparseable peer address must yield an empty client host, got %q", host)
		}
	})
}
