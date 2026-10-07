package fiber

import (
	"strings"

	fiberlib "github.com/gofiber/fiber/v3"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// The websocket handshake guard, ported from fastapi-guard guard/websocket.py
// (guard_websocket / make_guard_websocket): the reference HTTP middleware
// never sees websocket connections (Starlette routes them separately), so
// the guard runs as an explicit dependency in the websocket handler before
// the upgrade. Fiber exposes the upgrade through the fasthttp request
// context: call GuardWebSocket before upgrading and reject the handshake
// when it answers a close reason (a rejected upgrade has no websocket to
// close, so the reason maps onto an HTTP status through
// WebSocketHTTPStatus; a handler that already accepted can close with the
// reason's code and reason string verbatim).

// GuardWebSocket runs the engine's websocket handshake checks over the
// upgrade request: identity resolution, the fail-secure unknown-address
// close, the ban check, the is_ip_allowed verdict, the ws rate limit, and
// the penetration detection pass sharing the HTTP pipeline's suspicious
// counts. A nil result allows the upgrade; a non-nil reason closes it. A
// nil engine fails closed with the security-check-failed reason.
func GuardWebSocket(engine *guardcore.Engine, c fiberlib.Ctx) *guardcore.WebSocketCloseReason {
	if engine == nil || c == nil {
		reason := guardcore.WSCloseSecurityCheckFailed
		return &reason
	}
	return engine.GuardWebSocket(newWSRequestShim(c))
}

// WebSocketHTTPStatus maps a close reason onto the HTTP status an upgrade
// rejection carries: 503 for the try-again-later security-check failure,
// 403 for every policy-violation reason, 200 for a nil (allowed) verdict.
func WebSocketHTTPStatus(reason *guardcore.WebSocketCloseReason) int {
	if reason == nil {
		return 200
	}
	if reason.Code == guardcore.WebSocketCloseTryAgainLater {
		return 503
	}
	return 403
}

// wsRequestShim mirrors the reference _WebSocketGuardRequest: method
// "WEBSOCKET", an empty body, repeated headers joined with ", "
// (_join_repeated_header_lines), and a fresh request state.
type wsRequestShim struct {
	c     fiberlib.Ctx
	state guardcore.RequestState
}

func newWSRequestShim(c fiberlib.Ctx) *wsRequestShim {
	return &wsRequestShim{c: c}
}

func (s *wsRequestShim) URLPath() string { return s.c.Path() }

func (s *wsRequestShim) URLScheme() string {
	if s.c.RequestCtx().IsTLS() {
		return "https"
	}
	return "http"
}

func (s *wsRequestShim) URLFull() string {
	full := s.URLScheme() + "://" + string(s.c.RequestCtx().Host()) + s.URLPath()
	if query := string(s.c.RequestCtx().URI().QueryString()); query != "" {
		full += "?" + query
	}
	return full
}

func (s *wsRequestShim) URLReplaceScheme(scheme string) string {
	full := s.URLFull()
	if scheme == "" {
		return full
	}
	return scheme + "://" + strings.TrimPrefix(strings.TrimPrefix(full, "http://"), "https://")
}

func (s *wsRequestShim) Method() string { return "WEBSOCKET" }

func (s *wsRequestShim) ClientHost() string {
	if ip := s.c.RequestCtx().RemoteIP(); ip != nil {
		return ip.String()
	}
	return ""
}

func (s *wsRequestShim) Headers() guardcore.Headers {
	headers := guardcore.NewHeaders()
	s.c.RequestCtx().Request.Header.All()(func(key, value []byte) bool {
		if existing, seen := headers.Get(string(key)); seen {
			// The reference ws request joins repeated header lines with
			// ", " (_join_repeated_header_lines).
			headers.Set(string(key), existing+", "+string(value))
			return true
		}
		headers.Set(string(key), string(value))
		return true
	})
	return headers
}

func (s *wsRequestShim) QueryParams() map[string]string {
	params := make(map[string]string)
	for key, value := range s.c.RequestCtx().QueryArgs().All() {
		if _, ok := params[string(key)]; !ok {
			params[string(key)] = string(value)
		}
	}
	return params
}

func (s *wsRequestShim) Body() ([]byte, error) { return nil, nil }

func (s *wsRequestShim) State() *guardcore.RequestState { return &s.state }
