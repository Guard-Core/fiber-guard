package fiber

import (
	"errors"
	"time"

	fiberlib "github.com/gofiber/fiber/v3"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// Status route, ported from fastapi-guard guard/status.py (add_status_route)
// serving the payload of guard_core HandlerInitializer.get_initialization_status
// (guard_core/core/initialization/handler_initializer.py): the cloud-provider
// table and the geo-ip snapshot, plus the nethttp sibling's per-component
// redis health (the Go engine exposes its redis manager directly, so the
// status route doubles as a live dependency probe).

// DefaultStatusPath is the route path add_status_route registers by default
// (the reference's /_guard/status).
const DefaultStatusPath = "/_guard/status"

// redisStatusProbeKeySuffix is the key the redis health probe PTTLs: O(1)
// server side, matches nothing, and redis.Nil (key not found) is swallowed
// by the manager like any other miss, so only a connection failure
// surfaces.
const redisStatusProbeKeySuffix = "__status_probe__"

// geoStatusProvider is the optional status surface of the configured
// CountryResolver: the built-in *guardcore.GeoIPManager implements it
// (GeoIPManager.GetStatus mirrors IPInfoManager.get_status), foreign
// resolvers may too. This mirrors the reference's getattr(geo_ip_handler,
// "get_status") fallback dance.
type geoStatusProvider interface {
	GetStatus() map[string]any
}

// ComponentStatus is one cloud provider's row of the reference
// cloud_handler.get_status payload.
type ComponentStatus struct {
	Ready         bool       `json:"ready"`
	LastRefreshed *time.Time `json:"last_refreshed"`
	Entries       int        `json:"entries"`
}

// RedisStatus is the redis component of the status payload: whether the
// engine was configured with redis, and - when it was - whether the manager
// answers a probe right now. ok defaults true when redis is disabled (there
// is nothing to be down), mirroring the PHP siblings' initialize() snapshot.
type RedisStatus struct {
	Enabled bool    `json:"enabled"`
	OK      bool    `json:"ok"`
	Error   *string `json:"error"`
}

// InitializationStatus is the JSON payload the status route serves.
type InitializationStatus struct {
	CloudProviders map[string]ComponentStatus `json:"cloud_providers"`
	GeoIP          map[string]any             `json:"geo_ip"`
	Redis          RedisStatus                `json:"redis"`
}

// initializationStatus snapshots the engine's initialization surface. It
// never mutates engine state: cloud and geo read the managers' current
// tables, and the redis probe answers from a live connection when the
// manager already has one (the app's startup Initialize()); a manager with
// no client yet dials lazily exactly like any other guard operation, so a
// status GET cannot fail a request the engine would otherwise have served.
func initializationStatus(engine *guardcore.Engine) InitializationStatus {
	status := InitializationStatus{
		CloudProviders: map[string]ComponentStatus{},
		GeoIP:          geoIPStatus(engine),
		Redis:          redisStatus(engine),
	}
	for provider, raw := range engine.Cloud.Status() {
		// A provider that never refreshed carries the zero time; the
		// reference's last_updated.get(provider) reports null there.
		var refreshed *time.Time
		if !raw.LastRefreshed.IsZero() {
			refreshed = &raw.LastRefreshed
		}
		status.CloudProviders[provider] = ComponentStatus{
			Ready:         raw.Ready,
			LastRefreshed: refreshed,
			Entries:       raw.Entries,
		}
	}
	return status
}

// geoIPStatus serves the geo_ip component: the handler's own get_status
// snapshot when it provides one (the built-in manager does), nil otherwise
// - the reference reports null geo_ip when no handler is configured.
func geoIPStatus(engine *guardcore.Engine) map[string]any {
	provider, ok := engine.Config.GeoIPHandler.(geoStatusProvider)
	if !ok {
		return nil
	}
	return provider.GetStatus()
}

// redisStatus serves the redis component: enabled plus a live probe. A
// disabled manager reports enabled=false, ok=true, error=null; a probe
// failure reports ok=false with the redacted failure string.
func redisStatus(engine *guardcore.Engine) RedisStatus {
	status := RedisStatus{Enabled: engine.Redis.Enabled(), OK: true}
	if !status.Enabled {
		return status
	}
	if _, err := engine.Redis.PTTL(engine.Redis.Prefix() + redisStatusProbeKeySuffix); err != nil {
		message := err.Error()
		status.OK = false
		status.Error = &message
	}
	return status
}

// NewStatusHandler returns the fiber handler serving the engine's
// initialization status JSON (the reference guard_initialization_status).
// Mount it behind the security middleware like any other route and exclude
// it from the checks via the config's path exclusions when it should answer
// unguarded.
func NewStatusHandler(engine *guardcore.Engine) (fiberlib.Handler, error) {
	if engine == nil {
		return nil, errors.New("engine must not be nil")
	}
	return func(c fiberlib.Ctx) error {
		return c.Status(200).JSON(initializationStatus(engine))
	}, nil
}

// AddStatusRoute registers the status handler on the fiber app at path (the
// empty string picks DefaultStatusPath), mirroring fastapi-guard
// add_status_route:
//
//	if err := fiber.AddStatusRoute(app, engine, ""); err != nil { ... }
//
// The method-scoped route answers GET only; other methods fall through to
// the framework's not-found handling.
func AddStatusRoute(app *fiberlib.App, engine *guardcore.Engine, path string) error {
	if app == nil {
		return errors.New("app must not be nil")
	}
	handler, err := NewStatusHandler(engine)
	if err != nil {
		return err
	}
	if path == "" {
		path = DefaultStatusPath
	}
	app.Get(path, handler)
	return nil
}
