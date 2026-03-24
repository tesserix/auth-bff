package gip

import (
	"context"

	firebaseauth "firebase.google.com/go/v4/auth"

	"github.com/tesserix/auth-bff/internal/config"
)

// Ensure Firebase Auth SDK is importable (validates go.mod dependency).
var _ *firebaseauth.Client

// AuthProvider is the full interface needed by AuthHandler: OIDC flow methods + token verification + revocation.
// *Client satisfies this interface. Tests can use MockAuthProvider or compose with MockTokenVerifier.
type AuthProvider interface {
	TokenVerifier
	AuthURL(app *config.AppConfig, state, nonce, codeVerifier, redirectURI string) (string, error)
	Exchange(ctx context.Context, app *config.AppConfig, code, codeVerifier, redirectURI string) (*TokenSet, error)
	Refresh(ctx context.Context, app *config.AppConfig, refreshToken string) (*TokenSet, error)
}

// Compile-time interface check: *Client satisfies AuthProvider.
var _ AuthProvider = (*Client)(nil)

// TokenVerifier abstracts Firebase Admin SDK TenantClient.VerifyIDToken for testing.
// The production implementation uses firebaseauth.Client; tests use MockTokenVerifier.
type TokenVerifier interface {
	// VerifyIDToken verifies a raw GIP ID token for the given app's tenant pool.
	// Returns IDTokenClaims on success; error if token is invalid or from wrong pool.
	VerifyIDToken(ctx context.Context, app *config.AppConfig, rawIDToken string) (*IDTokenClaims, error)

	// RevokeTokens revokes all GIP refresh tokens for the given user UID.
	// Non-fatal on error -- always log but never block logout.
	RevokeTokens(ctx context.Context, app *config.AppConfig, userUID string) error
}

// MockTokenVerifier is a test double for TokenVerifier.
// Fields control return values; callers inspect call records for assertions.
type MockTokenVerifier struct {
	// VerifyIDTokenFn overrides VerifyIDToken behavior. If nil, returns VerifyResult/VerifyErr.
	VerifyIDTokenFn func(ctx context.Context, app *config.AppConfig, rawIDToken string) (*IDTokenClaims, error)
	// RevokeTokensFn overrides RevokeTokens behavior. If nil, returns RevokeErr.
	RevokeTokensFn func(ctx context.Context, app *config.AppConfig, userUID string) error

	VerifyResult *IDTokenClaims
	VerifyErr    error
	RevokeErr    error

	VerifyCalled int
	RevokeCalled int
	LastTenantID string // records app.GIPTenantID on each call
}

// Compile-time interface check.
var _ TokenVerifier = (*MockTokenVerifier)(nil)

func (m *MockTokenVerifier) VerifyIDToken(ctx context.Context, app *config.AppConfig, rawIDToken string) (*IDTokenClaims, error) {
	m.VerifyCalled++
	m.LastTenantID = app.GIPTenantID
	if m.VerifyIDTokenFn != nil {
		return m.VerifyIDTokenFn(ctx, app, rawIDToken)
	}
	return m.VerifyResult, m.VerifyErr
}

func (m *MockTokenVerifier) RevokeTokens(ctx context.Context, app *config.AppConfig, userUID string) error {
	m.RevokeCalled++
	if m.RevokeTokensFn != nil {
		return m.RevokeTokensFn(ctx, app, userUID)
	}
	return m.RevokeErr
}

// MockAuthProvider is a test double for AuthProvider.
// Embeds MockTokenVerifier for VerifyIDToken/RevokeTokens and stubs OIDC flow methods.
type MockAuthProvider struct {
	MockTokenVerifier
	AuthURLResult string
	AuthURLErr    error
	ExchangeResult *TokenSet
	ExchangeErr   error
	RefreshResult *TokenSet
	RefreshErr    error
}

// Compile-time interface check.
var _ AuthProvider = (*MockAuthProvider)(nil)

func (m *MockAuthProvider) AuthURL(_ *config.AppConfig, _, _, _, _ string) (string, error) {
	return m.AuthURLResult, m.AuthURLErr
}

func (m *MockAuthProvider) Exchange(_ context.Context, _ *config.AppConfig, _, _, _ string) (*TokenSet, error) {
	return m.ExchangeResult, m.ExchangeErr
}

func (m *MockAuthProvider) Refresh(_ context.Context, _ *config.AppConfig, _ string) (*TokenSet, error) {
	return m.RefreshResult, m.RefreshErr
}
