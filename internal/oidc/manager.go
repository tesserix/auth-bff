package oidc

import (
	"context"
	"fmt"
	"sync"

	"github.com/tesserix/auth-bff/internal/config"
)

// Manager manages OIDC providers for multiple realms.
type Manager struct {
	providers map[string]Provider // realm name → provider
	mu        sync.RWMutex
}

// NewManager creates a Manager and initializes providers for all configured realms.
func NewManager(ctx context.Context, cfg *config.Config) (*Manager, error) {
	m := &Manager{
		providers: make(map[string]Provider),
	}

	// Internal realm (admin, home, onboarding)
	internalIssuer := fmt.Sprintf("%s/realms/%s", cfg.KeycloakURL, cfg.InternalRealm)
	internalInternal := ""
	if cfg.KeycloakInternalURL != "" {
		internalInternal = fmt.Sprintf("%s/realms/%s", cfg.KeycloakInternalURL, cfg.InternalRealm)
	}

	internalProvider, err := NewKeycloakProvider(ctx, ProviderConfig{
		IssuerURL:    internalIssuer,
		InternalURL:  internalInternal,
		ClientID:     cfg.InternalClientID,
		ClientSecret: cfg.InternalClientSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("internal provider: %w", err)
	}
	m.providers[cfg.InternalRealm] = internalProvider

	// Customer realm (storefront)
	customerIssuer := fmt.Sprintf("%s/realms/%s", cfg.KeycloakURL, cfg.CustomerRealm)
	customerInternal := ""
	if cfg.KeycloakInternalURL != "" {
		customerInternal = fmt.Sprintf("%s/realms/%s", cfg.KeycloakInternalURL, cfg.CustomerRealm)
	}

	customerProvider, err := NewKeycloakProvider(ctx, ProviderConfig{
		IssuerURL:    customerIssuer,
		InternalURL:  customerInternal,
		ClientID:     cfg.CustomerClientID,
		ClientSecret: cfg.CustomerClientSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("customer provider: %w", err)
	}
	m.providers[cfg.CustomerRealm] = customerProvider

	return m, nil
}

// GetProvider returns the OIDC provider for the given realm.
func (m *Manager) GetProvider(realm string) (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.providers[realm]
	if !ok {
		return nil, fmt.Errorf("no OIDC provider for realm %q", realm)
	}
	return p, nil
}

// GetProviderForApp returns the OIDC provider for an app config.
func (m *Manager) GetProviderForApp(app *config.AppConfig) (Provider, error) {
	return m.GetProvider(app.Realm)
}
