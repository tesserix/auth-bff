// Package gip provides Google Identity Platform integration.
// GIP replaces Keycloak — each GIP tenant is a separate user pool (like a realm).
//
// Supports two auth flows:
//  1. OIDC Authorization Code + PKCE (server-side redirect flow)
//  2. Token verification (frontend uses Firebase Auth SDK, sends ID token to BFF)
package gip

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/tesserix/auth-bff/internal/config"
)

// TokenSet holds tokens from an OIDC exchange or refresh.
type TokenSet struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresAt    time.Time
}

// IDTokenClaims holds verified claims from a GIP ID token.
type IDTokenClaims struct {
	Subject       string         `json:"sub"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Name          string         `json:"name"`
	GivenName     string         `json:"given_name"`
	FamilyName    string         `json:"family_name"`
	Picture       string         `json:"picture"`
	Firebase      *firebaseClaim `json:"firebase"` // nested GIP metadata
	TenantID      string         `json:"-"`         // populated from Firebase.Tenant after decode
	Nonce         string         `json:"nonce"`     // OIDC nonce for replay protection
}

// firebaseClaim represents the nested "firebase" claim in GIP/Firebase ID tokens.
type firebaseClaim struct {
	Tenant         string `json:"tenant"`
	SignInProvider string `json:"sign_in_provider"`
}

// Client manages OIDC providers for Google Identity Platform tenants.
type Client struct {
	projectID string
	providers map[string]*provider // keyed by gipTenantID:oauthClientID
	mu        sync.RWMutex
}

type provider struct {
	oidcProvider   *gooidc.Provider
	verifier       *gooidc.IDTokenVerifier // GIP/Firebase issuer (securetoken.google.com)
	googleVerifier *gooidc.IDTokenVerifier // Google OAuth issuer (accounts.google.com)
	oauth2Config   *oauth2.Config
	gipTenantID    string
}

// NewClient initializes GIP OIDC providers for all configured apps.
func NewClient(ctx context.Context, cfg *config.Config) (*Client, error) {
	c := &Client{
		projectID: cfg.GCPProjectID,
		providers: make(map[string]*provider),
	}

	seen := make(map[string]bool)
	for _, app := range cfg.Apps {
		key := app.GIPTenantID + ":" + app.OAuthClientID
		if seen[key] {
			continue
		}
		seen[key] = true

		// GIP/Firebase OIDC issuer — tokens are issued by securetoken.google.com/{projectID}
		gipProv, err := gooidc.NewProvider(ctx, fmt.Sprintf("https://securetoken.google.com/%s", cfg.GCPProjectID))
		if err != nil {
			return nil, fmt.Errorf("gip: init gip oidc provider for %s: %w", key, err)
		}

		// Google OAuth OIDC issuer — tokens from the authorization code flow are
		// issued by accounts.google.com (not by GIP/securetoken).
		googleProv, err := gooidc.NewProvider(ctx, "https://accounts.google.com")
		if err != nil {
			return nil, fmt.Errorf("gip: init google oidc provider for %s: %w", key, err)
		}

		p := &provider{
			oidcProvider: gipProv,
			verifier: gipProv.Verifier(&gooidc.Config{
				ClientID: app.OAuthClientID,
			}),
			googleVerifier: googleProv.Verifier(&gooidc.Config{
				ClientID: app.OAuthClientID,
			}),
			oauth2Config: &oauth2.Config{
				ClientID:     app.OAuthClientID,
				ClientSecret: app.OAuthClientSecret,
				Endpoint:     google.Endpoint,
				Scopes:       []string{gooidc.ScopeOpenID, "profile", "email"},
			},
			gipTenantID: app.GIPTenantID,
		}
		c.providers[key] = p
	}

	return c, nil
}

// AuthURL generates the OIDC authorization URL with PKCE.
func (c *Client) AuthURL(app *config.AppConfig, state, nonce, codeVerifier, redirectURI string) (string, error) {
	p, err := c.getProvider(app)
	if err != nil {
		return "", err
	}

	cfg := *p.oauth2Config
	cfg.RedirectURL = redirectURI

	// S256 PKCE challenge
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.AccessTypeOffline, // get refresh token
	}

	return cfg.AuthCodeURL(state, opts...), nil
}

// Exchange trades an authorization code for tokens.
func (c *Client) Exchange(ctx context.Context, app *config.AppConfig, code, codeVerifier, redirectURI string) (*TokenSet, error) {
	p, err := c.getProvider(app)
	if err != nil {
		return nil, err
	}

	cfg := *p.oauth2Config
	cfg.RedirectURL = redirectURI

	token, err := cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("gip: exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("gip: no id_token in response")
	}

	return &TokenSet{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}, nil
}

// Refresh uses a refresh token to get new tokens.
func (c *Client) Refresh(ctx context.Context, app *config.AppConfig, refreshToken string) (*TokenSet, error) {
	p, err := c.getProvider(app)
	if err != nil {
		return nil, err
	}

	src := p.oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	token, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("gip: refresh token: %w", err)
	}

	rawIDToken, _ := token.Extra("id_token").(string)

	return &TokenSet{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}, nil
}

// VerifyIDToken verifies an ID token and extracts claims.
// Tries the Google OAuth verifier first (for tokens from the authorization code flow),
// then falls back to the GIP/Firebase verifier (for tokens from the Firebase Auth SDK).
func (c *Client) VerifyIDToken(ctx context.Context, app *config.AppConfig, rawIDToken string) (*IDTokenClaims, error) {
	p, err := c.getProvider(app)
	if err != nil {
		return nil, err
	}

	// Try Google OAuth issuer first (accounts.google.com)
	idToken, err := p.googleVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		// Fall back to GIP/Firebase issuer (securetoken.google.com)
		idToken, err = p.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return nil, fmt.Errorf("gip: verify id token: %w", err)
		}
	}

	var claims IDTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("gip: extract claims: %w", err)
	}
	claims.Subject = idToken.Subject
	// Populate TenantID from nested firebase.tenant claim
	if claims.Firebase != nil && claims.Firebase.Tenant != "" {
		claims.TenantID = claims.Firebase.Tenant
	}

	return &claims, nil
}

// PasswordSignInResult holds the response from the GIP REST API signInWithPassword call.
type PasswordSignInResult struct {
	IDToken      string
	RefreshToken string
	ExpiresIn    int
	LocalID      string // Firebase UID
	Email        string
}

// SignInWithPassword authenticates a user via the GIP REST API using email + password.
// This returns real idToken + refreshToken without an OIDC redirect flow.
// Used for cross-origin session bootstrapping after onboarding account creation.
func (c *Client) SignInWithPassword(ctx context.Context, apiKey, gipTenantID, email, password string) (*PasswordSignInResult, error) {
	endpoint := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", apiKey)

	payload := map[string]interface{}{
		"email":             email,
		"password":          password,
		"returnSecureToken": true,
	}
	if gipTenantID != "" {
		payload["tenantId"] = gipTenantID
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("gip: marshal signin request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gip: create signin request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gip: signin request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		IDToken      string `json:"idToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    string `json:"expiresIn"`
		LocalID      string `json:"localId"`
		Email        string `json:"email"`
		Error        *struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("gip: decode signin response: %w", err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("gip: signin failed: %s (code %d)", result.Error.Message, result.Error.Code)
	}
	if result.IDToken == "" {
		return nil, fmt.Errorf("gip: signin returned no id_token")
	}

	expiresIn := 3600
	if result.ExpiresIn != "" {
		fmt.Sscanf(result.ExpiresIn, "%d", &expiresIn)
	}

	return &PasswordSignInResult{
		IDToken:      result.IDToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    expiresIn,
		LocalID:      result.LocalID,
		Email:        result.Email,
	}, nil
}

func (c *Client) getProvider(app *config.AppConfig) (*provider, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := app.GIPTenantID + ":" + app.OAuthClientID
	p, ok := c.providers[key]
	if !ok {
		return nil, fmt.Errorf("gip: no provider for app %s (key: %s)", app.Name, key)
	}
	return p, nil
}
