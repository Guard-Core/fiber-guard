package fiber

import (
	fiberlib "github.com/gofiber/fiber/v3"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// applyModifier runs the engine's CustomResponseModifier over the finished
// pass-through response, the last step of the reference response factory's
// process_response. Fiber already buffers the response, so no capture layer
// is needed. Headers the modifier did not touch keep every value
// (Set-Cookie and friends); changed or added ones are set, removed ones are
// deleted. CORS headers are applied again afterwards, as the reference
// dispatch injects them on the processed response.
func applyModifier(c fiberlib.Ctx, engine *guardcore.Engine, cors map[string]string) {
	header := &c.Response().Header
	snapshot := make(map[string]string)
	header.All()(func(key, value []byte) bool {
		if _, seen := snapshot[string(key)]; !seen {
			snapshot[string(key)] = string(value)
		}
		return true
	})
	before := make(map[string]string, len(snapshot))
	for name, value := range snapshot {
		before[name] = value
	}
	out := engine.ModifyResponse(&guardcore.Response{
		StatusCode: c.Response().StatusCode(),
		Headers:    snapshot,
		Body:       append([]byte(nil), c.Response().Body()...),
	})
	for name := range before {
		if _, kept := out.Headers[name]; !kept {
			header.Del(name)
		}
	}
	for name, value := range out.Headers {
		if prev, seen := before[name]; !seen || prev != value {
			header.Set(name, value)
		}
	}
	for name, value := range cors {
		header.Set(name, value)
	}
	c.Response().SetStatusCode(out.StatusCode)
	c.Response().SetBodyRaw(out.Body)
}
