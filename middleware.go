package fiber

import (
	"errors"
	"fmt"
	"log"

	fiberlib "github.com/gofiber/fiber/v3"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const failClosedMessage = "Security check failed"

type middleware struct {
	engine   *guardcore.Engine
	maxBytes int64
	logger   *log.Logger
}

type Option func(*middleware)

func WithMaxBodyBytes(maxBodyBytes int64) Option {
	return func(m *middleware) {
		if maxBodyBytes > 0 {
			m.maxBytes = maxBodyBytes
		}
	}
}

func WithLogger(logger *log.Logger) Option {
	return func(m *middleware) {
		if logger != nil {
			m.logger = logger
		}
	}
}

func New(engine *guardcore.Engine, opts ...Option) (fiberlib.Handler, error) {
	if engine == nil {
		return nil, errors.New("engine must not be nil")
	}
	m := &middleware{engine: engine, maxBytes: DefaultMaxBodyBytes, logger: log.Default()}
	for _, opt := range opts {
		opt(m)
	}
	return m.wrap, nil
}

func (m *middleware) wrap(c fiberlib.Ctx) error {
	req := newRequestShim(c, m.maxBytes)
	verdict, err := m.check(req)
	if err != nil {
		m.logger.Printf("guardcore fiber: engine malfunction, failing closed: %v", err)
		applyResponse(c, m.engine.CreateErrorResponse(500, failClosedMessage))
		return nil
	}
	if verdict != nil {
		applyResponse(c, verdict)
		return nil
	}
	// Security headers on the pass-through path: the engine computes the
	// set (blocked verdicts already carry it), the adapter applies it
	// before the handler writes its response. CORS response headers are
	// merged on top (the reference _inject_cors_headers runs after the
	// security-header set, so CORS wins on a shared name) whenever the
	// request carries an Origin and CORS is enabled.
	headers := m.engine.ResponseHeaders()
	for name, value := range m.engine.CORSResponseHeaders(req) {
		headers[name] = value
	}
	for name, value := range headers {
		c.Set(name, value)
	}
	err = c.Next()
	// Behavioral return rules (route and global) run against the response
	// the handler produced, exactly like the reference response factory's
	// behavioral phase. Fiber buffers the response, so after the chain runs
	// the adapter hands the engine the status and the leading response body
	// bytes up to the configured inspect budget (return rules never modify
	// the response).
	var observedBody []byte
	if m.engine.Config.BehaviorScanResponseBody {
		if budget := m.engine.Config.BehaviorMaxResponseBodyInspectBytes; budget > 0 {
			body := c.Response().Body()
			if len(body) > budget {
				body = body[:budget]
			}
			observedBody = body
		}
	}
	m.engine.ProcessResponse(req, &guardcore.Response{
		StatusCode: c.Response().StatusCode(),
		Headers:    map[string]string{},
		Body:       observedBody,
	})
	return err
}

func (m *middleware) check(req guardcore.Request) (verdict *guardcore.Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("engine panic: %v", r)
		}
	}()
	return m.engine.Check(req), nil
}

func applyResponse(c fiberlib.Ctx, response *guardcore.Response) {
	for name, value := range response.Headers {
		c.Set(name, value)
	}
	c.Status(response.StatusCode)
	if len(response.Body) > 0 {
		_, _ = c.Write(response.Body)
	}
	// Aborting in Fiber means returning without calling c.Next().
}
