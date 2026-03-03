package oidc

import (
	"context"
	"fmt"
	"sync"

	"github.com/tesserix/auth-bff/internal/config"
)

// Manager manages OIDC providers keyed by realm:clientId.
type Manager struct {
	providers map[string]Provider
	mu        sync.RWMutex
}

// NewManager creates a Manager and initializes providers for all unique
// realm:clientId combinations found across the configured apps.
func NewManager(ctx context.Context, cfg *config.Config) (*Manager, error) {
	m := &Manager{
		providers: make(map[string]Provider),
	}

	seen := make(map[string]bool)
	for _, app := range cfg.Apps {
		key := app.Realm + ":" + app.ClientID
		if seen[key] {
			continue
		}
		seen[key] = true

		baseURL := cfg.KeycloakURL
		internalURL := cfg.KeycloakInternalURL

		// Use customer Keycloak URLs for customer realm
		if app.Realm == cfg.CustomerRealm {
			baseURL = cfg.CustomerKeycloakPublicURL()
			if u := cfg.CustomerKeycloakDiscoveryURL(); u != "" {
				internalURL = u
			}
		}

		issuer := fmt.Sprintf("%s/realms/%s", baseURL, app.Realm)
		internal := ""
		if internalURL != "" {
			internal = fmt.Sprintf("%s/realms/%s", internalURL, app.Realm)
		}

		provider, err := NewKeycloakProvider(ctx, ProviderConfig{
			IssuerURL:    issuer,
			InternalURL:  internal,
			ClientID:     app.ClientID,
			ClientSecret: app.ClientSecret,
		})
		if err != nil {
			return nil, fmt.Errorf("provider %s: %w", key, err)
		}
		m.providers[key] = provider
	}

	return m, nil
}

// GetProvider returns the OIDC provider for the given key (realm:clientId).
func (m *Manager) GetProvider(key string) (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.providers[key]
	if !ok {
		return nil, fmt.Errorf("no OIDC provider for key %q", key)
	}
	return p, nil
}

// GetProviderForApp returns the OIDC provider for an app config.
func (m *Manager) GetProviderForApp(app *config.AppConfig) (Provider, error) {
	key := app.Realm + ":" + app.ClientID
	return m.GetProvider(key)
}
