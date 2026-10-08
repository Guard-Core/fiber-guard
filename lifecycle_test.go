package fiber

// The adapter lifecycle surface tests: mark_initialized /
// get_initialization_status / reset / agent_stats / refresh_cloud_ip_ranges
// (fastapi-guard guard/middleware.py), each over the engine handle.

import (
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

type statsAgentHandler struct {
	guardcore.AgentHandlerFunc
	stats map[string]any
}

func (s *statsAgentHandler) AgentStats() map[string]any { return s.stats }

type bareAgentHandler struct{ guardcore.AgentHandlerFunc }

func TestMarkInitializedSkipsStartupIO(t *testing.T) {
	cfg := guardcore.DefaultSecurityConfig()
	cfg.EnableRedis = true
	cfg.RedisURL = "redis://127.0.0.1:1"
	cfg.RedisFailOpen = false
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	// The redis endpoint is unreachable, so a real startup would fail
	// closed: marking initialized must make Initialize a no-op.
	MarkInitialized(engine)
	if err := engine.Initialize(); err != nil {
		t.Fatalf("a marked-initialized engine must skip the startup I/O, got %v", err)
	}
	MarkInitialized(nil) // the defensive no-op arm
}

func TestGetInitializationStatus(t *testing.T) {
	if _, err := GetInitializationStatus(nil); err == nil {
		t.Fatal("a nil engine must error")
	}
	engine := newTestEngine(t, nil)
	status, err := GetInitializationStatus(engine)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.CloudProviders == nil {
		t.Fatal("the payload must carry the cloud_providers table")
	}
}

func TestResetDropsRateLimitState(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.RateLimit = 1
		c.RateLimitWindow = 60
	})
	first, err := engine.RateLimit.CheckRateLimitByIP("203.0.113.77", "reset-test")
	if err != nil || !first {
		t.Fatalf("the first request must pass, got (%v, %v)", first, err)
	}
	second, err := engine.RateLimit.CheckRateLimitByIP("203.0.113.77", "reset-test")
	if err != nil || second {
		t.Fatalf("the second request must trip the limit, got (%v, %v)", second, err)
	}
	Reset(engine)
	third, err := engine.RateLimit.CheckRateLimitByIP("203.0.113.77", "reset-test")
	if err != nil || !third {
		t.Fatalf("after the reset the window must be dropped, got (%v, %v)", third, err)
	}
	Reset(nil)                 // the defensive no-op arm
	Reset(&guardcore.Engine{}) // the nil-manager arm
}

func TestAgentStats(t *testing.T) {
	if stats := AgentStats(nil); stats["enabled"] != false {
		t.Fatalf("a nil engine must report disabled, got %v", stats)
	}
	agentless := newTestEngine(t, nil)
	if stats := AgentStats(agentless); stats["enabled"] != false || stats["degraded"] != false {
		t.Fatalf("an agentless engine must report disabled and not degraded, got %v", stats)
	}
	wired := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.EnableAgent = true
		c.AgentHandler = &statsAgentHandler{stats: map[string]any{"running": true}}
	})
	stats := AgentStats(wired)
	if stats["enabled"] != true || stats["running"] != true {
		t.Fatalf("a wired stats handler must merge its counters, got %v", stats)
	}
	bare := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.EnableAgent = true
		c.AgentHandler = &bareAgentHandler{}
	})
	if stats := AgentStats(bare); stats["enabled"] != true {
		t.Fatalf("a handler without the stats surface must still report enabled, got %v", stats)
	}
}

func TestRefreshCloudIPRangesWithoutRedis(t *testing.T) {
	if err := RefreshCloudIPRanges(nil); err == nil {
		t.Fatal("a nil engine must error")
	}
	empty := newTestEngine(t, nil)
	if err := RefreshCloudIPRanges(empty); err != nil {
		t.Fatalf("no blocked providers must be a no-op, got %v", err)
	}
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS"}
	})
	// A fresh manager keeps the shared package default untouched for the
	// other tests.
	engine.Cloud = guardcore.NewCloudManager()
	engine.Cloud.SetRangeFetcher(func(provider string) ([]string, map[string]string, error) {
		return []string{"203.0.113.0/24"}, nil, nil
	})
	defer engine.Cloud.SetRangeFetcher(nil)
	if err := RefreshCloudIPRanges(engine); err != nil {
		t.Fatalf("the in-memory refresh must answer, got %v", err)
	}
	status := engine.Cloud.Status()["AWS"]
	if !status.Ready || status.LastRefreshed.IsZero() {
		t.Fatalf("the refresh must install and stamp the provider ranges, got %+v", status)
	}
	if !engine.Cloud.IsCloudIP("203.0.113.9", []string{"AWS"}) {
		t.Fatal("the refreshed ranges must be enforceable")
	}
}
