package fiber

import (
	"encoding/json"
	"testing"

	fiberlib "github.com/gofiber/fiber/v3"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// fakeGeoResolver is a foreign CountryResolver carrying the optional
// get_status surface the status route picks up (the built-in GeoIPManager's
// GetStatus shape).
type fakeGeoResolver struct {
	status map[string]any
}

func (f *fakeGeoResolver) GetCountry(ip string) (string, bool) { return "", false }

func (f *fakeGeoResolver) GetStatus() map[string]any { return f.status }

func statusServe(t *testing.T, mutate func(*guardcore.SecurityConfig), path string) map[string]any {
	t.Helper()
	engine := newTestEngine(t, mutate)
	app := fiberlib.New()
	if err := AddStatusRoute(app, engine, path); err != nil {
		t.Fatalf("add status route: %v", err)
	}
	served := path
	if served == "" {
		served = DefaultStatusPath
	}
	resp := runFiberApp(t, app, "203.0.113.9:1234", newReq("GET", served, "", nil))
	if resp.StatusCode() != 200 {
		t.Fatalf("status route must answer 200, got %d", resp.StatusCode())
	}
	var payload map[string]any
	if err := json.Unmarshal(resp.Body(), &payload); err != nil {
		t.Fatalf("status payload must be JSON: %v", err)
	}
	return payload
}

func TestAddStatusRouteNilEngineRejected(t *testing.T) {
	if err := AddStatusRoute(fiberlib.New(), nil, ""); err == nil {
		t.Fatal("nil engine must be rejected")
	}
	if _, err := NewStatusHandler(nil); err == nil {
		t.Fatal("nil engine must be rejected")
	}
}

func TestAddStatusRouteNilAppRejected(t *testing.T) {
	engine := newTestEngine(t, nil)
	if err := AddStatusRoute(nil, engine, ""); err == nil {
		t.Fatal("nil app must be rejected")
	}
}

func TestStatusRouteDefaultPath(t *testing.T) {
	payload := statusServe(t, nil, "")
	if _, ok := payload["cloud_providers"]; !ok {
		t.Fatal("payload must carry cloud_providers")
	}
}

func TestStatusRouteCustomPath(t *testing.T) {
	payload := statusServe(t, nil, "/health/guard")
	if _, ok := payload["geo_ip"]; !ok {
		t.Fatal("payload must carry geo_ip")
	}
}

func TestStatusRouteCloudProvidersPayload(t *testing.T) {
	payload := statusServe(t, nil, "")
	raw, ok := payload["cloud_providers"].(map[string]any)
	if !ok {
		t.Fatal("cloud_providers must be an object")
	}
	if len(raw) == 0 {
		t.Fatal("cloud_providers must list the reference provider table")
	}
	for provider, entry := range raw {
		row, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("provider %s must be an object", provider)
		}
		if ready, ok := row["ready"].(bool); !ok || ready {
			t.Fatalf("provider %s must report ready=false before any refresh", provider)
		}
		if entries, ok := row["entries"].(float64); !ok || entries != 0 {
			t.Fatalf("provider %s must report entries=0 before any refresh, got %v", provider, entries)
		}
		if refreshed, ok := row["last_refreshed"]; !ok || refreshed != nil {
			t.Fatalf("provider %s must report last_refreshed=null before any refresh, got %v", provider, refreshed)
		}
	}
}

func TestStatusRouteGeoIPNullWithoutHandler(t *testing.T) {
	payload := statusServe(t, nil, "")
	if got, ok := payload["geo_ip"]; !ok || got != nil {
		t.Fatalf("geo_ip must be null without a configured handler, got %v", got)
	}
}

func TestStatusRouteGeoIPHandlerStatus(t *testing.T) {
	stub := &fakeGeoResolver{status: map[string]any{
		"ready":          true,
		"last_refreshed": "2026-10-06T00:00:00Z",
		"entries":        7,
	}}
	payload := statusServe(t, func(cfg *guardcore.SecurityConfig) {
		cfg.GeoIPHandler = stub
	}, "")
	geo, ok := payload["geo_ip"].(map[string]any)
	if !ok {
		t.Fatalf("geo_ip must serve the handler's get_status snapshot, got %v", payload["geo_ip"])
	}
	if ready, ok := geo["ready"].(bool); !ok || !ready {
		t.Fatalf("geo_ip.ready must pass the handler snapshot through, got %v", geo["ready"])
	}
}

func TestStatusRouteRedisDisabledReportsOK(t *testing.T) {
	payload := statusServe(t, nil, "")
	redis, ok := payload["redis"].(map[string]any)
	if !ok {
		t.Fatal("redis must be an object")
	}
	if enabled, _ := redis["enabled"].(bool); enabled {
		t.Fatal("redis must report enabled=false on a redisless engine")
	}
	if ok, _ := redis["ok"].(bool); !ok {
		t.Fatal("a disabled redis reports ok=true (there is nothing to be down)")
	}
}

func TestStatusRouteRedisUnreachable(t *testing.T) {
	// A refused dial fails immediately (no dial-timeout wait); the lazy
	// probe reports the failure instead of pretending to be healthy.
	payload := statusServe(t, func(cfg *guardcore.SecurityConfig) {
		cfg.EnableRedis = true
		cfg.RedisURL = "redis://127.0.0.1:1/0"
	}, "")
	redis, ok := payload["redis"].(map[string]any)
	if !ok {
		t.Fatal("redis must be an object")
	}
	if enabled, ok := redis["enabled"].(bool); !ok || !enabled {
		t.Fatalf("redis.enabled must mirror the config, got %v", redis["enabled"])
	}
	if ok, _ := redis["ok"].(bool); ok {
		t.Fatalf("redis.ok must be false when the probe cannot reach redis, got %v", redis)
	}
	if err, ok := redis["error"].(string); !ok || err == "" {
		t.Fatalf("redis.error must carry the probe failure, got %v", redis["error"])
	}
}

func TestStatusRouteCloudProviderRefreshSnapshot(t *testing.T) {
	engine := newTestEngine(t, nil)
	// A private manager (Engine.Cloud is an exported field): the package
	// default is a process global, and this test must not leak readiness
	// into the sibling assertions.
	engine.Cloud = guardcore.NewCloudManager()
	engine.Cloud.SetRangeFetcher(func(provider string) ([]string, map[string]string, error) {
		return []string{"203.0.113.0/24"}, nil, nil
	})
	if err := engine.Cloud.RefreshAsync([]string{"AWS"}, 300); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	app := fiberlib.New()
	if err := AddStatusRoute(app, engine, ""); err != nil {
		t.Fatalf("add status route: %v", err)
	}
	resp := runFiberApp(t, app, "203.0.113.9:1234", newReq("GET", DefaultStatusPath, "", nil))
	var payload map[string]any
	if err := json.Unmarshal(resp.Body(), &payload); err != nil {
		t.Fatalf("status payload must be JSON: %v", err)
	}
	raw := payload["cloud_providers"].(map[string]any)
	aws, ok := raw["AWS"].(map[string]any)
	if !ok {
		t.Fatalf("AWS must be a row, got %v", raw)
	}
	if ready, ok := aws["ready"].(bool); !ok || !ready {
		t.Fatalf("a refreshed provider must report ready=true, got %v", aws["ready"])
	}
	if refreshed, ok := aws["last_refreshed"].(string); !ok || refreshed == "" {
		t.Fatalf("a refreshed provider must carry a last_refreshed stamp, got %v", aws["last_refreshed"])
	}
	gcp, ok := raw["GCP"].(map[string]any)
	if !ok {
		t.Fatalf("GCP must be a row, got %v", raw)
	}
	if refreshed, ok := gcp["last_refreshed"]; !ok || refreshed != nil {
		t.Fatalf("a never-refreshed provider must report last_refreshed=null, got %v", refreshed)
	}
}
