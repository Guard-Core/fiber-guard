package fiber

import (
	"context"
	"strings"
	"sync"

	fiberlib "github.com/gofiber/fiber/v3"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const DefaultMaxBodyBytes int64 = 262144

type routeIDContextKey struct{}

func WithRouteID(ctx context.Context, routeID string) context.Context {
	return context.WithValue(ctx, routeIDContextKey{}, routeID)
}

type requestShim struct {
	c        fiberlib.Ctx
	state    guardcore.RequestState
	maxBytes int64

	mu    sync.Mutex
	cache []byte
}

var _ guardcore.Request = (*requestShim)(nil)

func newRequestShim(c fiberlib.Ctx, maxBodyBytes int64) *requestShim {
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	shim := &requestShim{c: c, maxBytes: maxBodyBytes}
	if routeID, ok := c.Context().Value(routeIDContextKey{}).(string); ok {
		shim.state.GuardRouteID = routeID
	}
	return shim
}

func (s *requestShim) URLPath() string { return s.c.Path() }

func (s *requestShim) URLScheme() string {
	if s.c.RequestCtx().IsTLS() {
		return "https"
	}
	return "http"
}

func (s *requestShim) URLFull() string {
	full := s.URLScheme() + "://" + string(s.c.RequestCtx().Host()) + s.URLPath()
	if query := string(s.c.RequestCtx().URI().QueryString()); query != "" {
		full += "?" + query
	}
	return full
}

func (s *requestShim) URLReplaceScheme(scheme string) string {
	full := s.URLFull()
	if scheme == "" {
		return full
	}
	return scheme + "://" + strings.TrimPrefix(strings.TrimPrefix(full, "http://"), "https://")
}

func (s *requestShim) Method() string {
	if s.c.Method() == "" {
		return "GET"
	}
	return strings.ToUpper(s.c.Method())
}

func (s *requestShim) ClientHost() string {
	if ip := s.c.RequestCtx().RemoteIP(); ip != nil {
		return ip.String()
	}
	return ""
}

func (s *requestShim) Headers() guardcore.Headers {
	headers := guardcore.NewHeaders()
	s.c.RequestCtx().Request.Header.All()(func(key, value []byte) bool {
		if _, seen := headers.Get(string(key)); !seen {
			headers.Set(string(key), string(value))
		}
		return true
	})
	return headers
}

func (s *requestShim) QueryParams() map[string]string {
	params := make(map[string]string)
	for key, value := range s.c.RequestCtx().QueryArgs().All() {
		if _, ok := params[string(key)]; !ok {
			params[string(key)] = string(value)
		}
	}
	return params
}

func (s *requestShim) Body() ([]byte, error) {
	return s.ReadBodyPrefix(int(s.maxBytes))
}

func (s *requestShim) State() *guardcore.RequestState { return &s.state }

func (s *requestShim) ReadBodyPrefix(maxBytes int) ([]byte, error) {
	if maxBytes < 0 {
		maxBytes = 0
	}
	if int64(maxBytes) > s.maxBytes {
		maxBytes = int(s.maxBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxBytes > len(s.cache) {
		body := s.c.Body()
		if ceiling := len(body); maxBytes > ceiling {
			maxBytes = ceiling
		}
		s.cache = append(s.cache, body[len(s.cache):maxBytes]...)
	}
	return s.cache, nil
}
