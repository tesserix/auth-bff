package appregistry

import (
	"strings"
	"sync"

	"github.com/tesserix/auth-bff/internal/config"
)

// Registry resolves incoming requests to their app configuration.
type Registry struct {
	apps []config.AppConfig
	mu   sync.RWMutex
}

// New creates a new Registry from the provided app configs.
func New(apps []config.AppConfig) *Registry {
	return &Registry{apps: apps}
}

// Resolve finds the AppConfig matching the given host.
// Host is typically from the x-forwarded-host header.
// Returns nil if no match is found.
func (r *Registry) Resolve(host string) *config.AppConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Extract first value from comma-separated x-forwarded-host
	host = extractFirstHost(host)
	host = strings.ToLower(strings.TrimSpace(host))

	if host == "" {
		return nil
	}

	// Priority order: home > onboarding > admin > storefront (most specific first)
	// Home and onboarding have exact hosts, admin has prefix patterns,
	// storefront is the catch-all wildcard.
	var storefrontApp *config.AppConfig

	for i := range r.apps {
		app := &r.apps[i]
		for _, pattern := range app.Hosts {
			if matchHost(host, pattern) {
				// Storefront is the catch-all — only use if nothing else matches
				if app.Name == "storefront" {
					storefrontApp = app
					continue
				}
				return app
			}
		}
	}

	return storefrontApp
}

// ResolveByName finds an AppConfig by its name.
func (r *Registry) ResolveByName(name string) *config.AppConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := range r.apps {
		if r.apps[i].Name == name {
			return &r.apps[i]
		}
	}
	return nil
}

// AllApps returns all registered app configs.
func (r *Registry) AllApps() []config.AppConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]config.AppConfig, len(r.apps))
	copy(out, r.apps)
	return out
}

// matchHost checks if a host matches a pattern. Supports * wildcard prefix.
// Examples:
//
//	"*-admin.tesserix.app" matches "demo-admin.tesserix.app"
//	"*.tesserix.app" matches "demo.tesserix.app"
//	"tesserix.app" matches "tesserix.app"
//	"localhost:3000" matches "localhost:3000"
func matchHost(host, pattern string) bool {
	pattern = strings.ToLower(pattern)

	if !strings.Contains(pattern, "*") {
		return host == pattern
	}

	// Handle *-prefix patterns like "*-admin.tesserix.app"
	// and simple wildcard patterns like "*.tesserix.app"
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:] // e.g., "-admin.tesserix.app" or ".tesserix.app"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}

	return false
}

// extractFirstHost gets the first host from a potentially comma-separated
// x-forwarded-host header value.
func extractFirstHost(host string) string {
	if idx := strings.IndexByte(host, ','); idx != -1 {
		return strings.TrimSpace(host[:idx])
	}
	return host
}
