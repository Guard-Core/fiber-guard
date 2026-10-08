package fiber

import (
	"errors"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// The adapter lifecycle surface, ported from fastapi-guard
// guard/middleware.py: mark_initialized (:131), get_initialization_status
// (:705), reset (:685), agent_stats (:256) and refresh_cloud_ip_ranges
// (:661). The reference middleware owns its machinery internally, so the
// ops are methods on SecurityMiddleware; this adapter's handle is the
// engine it wraps (New receives it), so the ops hang off explicit
// functions over the engine, the same seam as GuardWebSocket and
// AddStatusRoute. The engine side of the lifecycle (Initialize/Close,
// MarkInitialized, AgentStats) lives in guardcore.

// MarkInitialized marks the engine initialized without running the
// startup I/O (the reference mark_initialized: a stack warmed externally
// tells the middleware to consider itself initialized); a later
// engine.Initialize becomes a no-op.
func MarkInitialized(engine *guardcore.Engine) {
	if engine == nil {
		return
	}
	engine.MarkInitialized()
}

// GetInitializationStatus snapshots the engine's initialization surface
// (the reference get_initialization_status serving the handler
// initializer's payload): the cloud-provider table, the geo-ip snapshot
// and the redis probe. AddStatusRoute serves the same payload over HTTP.
func GetInitializationStatus(engine *guardcore.Engine) (InitializationStatus, error) {
	if engine == nil {
		return InitializationStatus{}, errors.New("engine must not be nil")
	}
	return initializationStatus(engine), nil
}

// Reset drops the rate limiter's state (the reference reset, which awaits
// rate_limit_handler.reset): the redis sliding windows and the in-memory
// fallback counters.
func Reset(engine *guardcore.Engine) {
	if engine == nil || engine.RateLimit == nil {
		return
	}
	engine.RateLimit.Reset()
}

// AgentStats mirrors the reference agent_stats property: agentless
// answers {"enabled": false, "degraded": <degraded>}; a wired handler
// answers {"enabled": true, "degraded": false} merged with its
// AgentStats() dict when it provides the stats surface.
func AgentStats(engine *guardcore.Engine) map[string]any {
	if engine == nil {
		return map[string]any{"enabled": false, "degraded": false}
	}
	return engine.AgentStats()
}

// RefreshCloudIPRanges refreshes the blocked cloud providers' ranges on
// demand (the reference refresh_cloud_ip_ranges): with redis configured
// the refresh runs through the redis-backed store at the configured TTL
// (the reference cloud_handler.refresh_async), otherwise in memory (the
// reference cloud_handler.refresh). A config without blocked providers
// is a no-op, exactly like the reference early return.
func RefreshCloudIPRanges(engine *guardcore.Engine) error {
	if engine == nil {
		return errors.New("engine must not be nil")
	}
	if len(engine.Config.BlockCloudProviders) == 0 {
		return nil
	}
	if engine.Config.EnableRedis {
		return engine.Cloud.InitializeRedis(engine.Redis, engine.Config.BlockCloudProviders, engine.Config.CloudIPRefreshInterval)
	}
	return engine.Cloud.RefreshAsync(engine.Config.BlockCloudProviders, engine.Config.CloudIPRefreshInterval)
}
