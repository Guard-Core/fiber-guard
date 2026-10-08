//go:build integration

package fiber

import (
	"context"
	"os"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// The redis arm of refresh_cloud_ip_ranges: the refresh runs through the
// redis-backed store (the reference cloud_handler.refresh_async with the
// configured TTL), answering from the cached ranges without a fetch.
func TestRefreshCloudIPRangesWithRedis(t *testing.T) {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	cfg := guardcore.DefaultSecurityConfig()
	cfg.EnableRedis = true
	cfg.RedisURL = "redis://" + host + ":6379"
	cfg.RedisPrefix = "guard_core_fiber_test:"
	cfg.RedisFailOpen = false
	cfg.BlockCloudProviders = []string{"AWS"}
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	// A fresh manager keeps the shared package default untouched for the
	// other tests; the pinned fetcher keeps the startup refresh away from
	// the provider registry (the fetch failure is the reference's
	// logged-and-tolerated arm).
	engine.Cloud = guardcore.NewCloudManager()
	engine.Cloud.SetRangeFetcher(func(provider string) ([]string, map[string]string, error) {
		return nil, nil, context.Canceled
	})
	defer engine.Cloud.SetRangeFetcher(nil)
	if err := engine.Initialize(); err != nil {
		t.Fatalf("engine initialize: %v", err)
	}
	t.Cleanup(func() {
		_, _ = engine.Redis.DeletePattern("cloud_ip_v2:*")
		_, _ = engine.Redis.DeletePattern("banned_ips:*")
		_, _ = engine.Redis.DeletePattern("rate_limit:rate:*")
		_ = engine.Close()
	})
	seed := guardcore.NewRedisCloudIPStore(engine.Redis)
	if err := seed.Set("AWS", []string{"198.51.100.0/24"}, 300); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	// The redis-backed refresh answers from the cache (the reference
	// refresh_async cached arm), so the seeded entry must be the one
	// enforced afterwards.
	if err := RefreshCloudIPRanges(engine); err != nil {
		t.Fatalf("the redis-backed refresh must answer from the cache, got %v", err)
	}
	status := engine.Cloud.Status()["AWS"]
	if !status.Ready || status.Entries != 1 {
		t.Fatalf("the cached range must be installed by the refresh, got %+v", status)
	}
	if !engine.Cloud.IsCloudIP("198.51.100.7", []string{"AWS"}) {
		t.Fatal("the cached range must be enforceable after the refresh")
	}
}
