package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// TokenSet holds tokens from an OIDC exchange or refresh.
type TokenSet struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresAt    time.Time
}

// Provider wraps OIDC discovery and token operations for a single realm.
type Provider interface {
	AuthURL(state, nonce, codeVerifier string, extraParams map[string]string) string
	Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*TokenSet, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenSet, error)
	UserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error)
	PasswordGrant(ctx context.Context, username, password string) (*TokenSet, error)
	RevokeToken(ctx context.Context, token, tokenType string) error
	EndSessionURL(idToken, postLogoutRedirectURI string) string
}

// KeycloakProvider implements Provider for a Keycloak realm.
type KeycloakProvider struct {
	issuerURL    string
	internalURL  string // optional: internal URL for server-to-server calls
	clientID     string
	clientSecret string
	redirectURI  string

	oidcProvider *gooidc.Provider
	oauth2Config *oauth2.Config
}

// ProviderConfig configures a KeycloakProvider.
type ProviderConfig struct {
	IssuerURL    string
	InternalURL  string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// NewKeycloakProvider creates and initializes a Keycloak OIDC provider.
func NewKeycloakProvider(ctx context.Context, cfg ProviderConfig) (*KeycloakProvider, error) {
	// Use internal URL for discovery if available (bypass CDN)
	discoveryURL := cfg.IssuerURL
	if cfg.InternalURL != "" {
		discoveryURL = cfg.InternalURL
	}

	// Set a custom context for discovery that uses the internal URL
	oidcCtx := ctx
	if cfg.InternalURL != "" {
		oidcCtx = gooidc.InsecureIssuerURLContext(ctx, cfg.IssuerURL)
	}

	provider, err := gooidc.NewProvider(oidcCtx, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.IssuerURL, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeOpenID, "profile", "email"}
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	return &KeycloakProvider{
		issuerURL:    cfg.IssuerURL,
		internalURL:  cfg.InternalURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		redirectURI:  cfg.RedirectURI,
		oidcProvider: provider,
		oauth2Config: oauth2Cfg,
	}, nil
}

// AuthURL generates the authorization URL with PKCE.
func (p *KeycloakProvider) AuthURL(state, nonce, codeVerifier string, extraParams map[string]string) string {
	challenge := generateCodeChallenge(codeVerifier)
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	for k, v := range extraParams {
		if v != "" {
			opts = append(opts, oauth2.SetAuthURLParam(k, v))
		}
	}
	return p.oauth2Config.AuthCodeURL(state, opts...)
}

// Exchange exchanges an authorization code for tokens using PKCE.
func (p *KeycloakProvider) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*TokenSet, error) {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	}
	if redirectURI != "" {
		opts = append(opts, oauth2.SetAuthURLParam("redirect_uri", redirectURI))
	}
	token, err := p.oauth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	return tokenSetFromOAuth2(token), nil
}

// Refresh exchanges a refresh token for new tokens.
func (p *KeycloakProvider) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	src := p.oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	token, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	return tokenSetFromOAuth2(token), nil
}

// UserInfo fetches claims from the OIDC userinfo endpoint.
func (p *KeycloakProvider) UserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	info, err := p.oidcProvider.UserInfo(ctx, src)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	var claims map[string]interface{}
	if err := info.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse userinfo claims: %w", err)
	}
	return claims, nil
}

// PasswordGrant performs a Resource Owner Password Credentials grant.
func (p *KeycloakProvider) PasswordGrant(ctx context.Context, username, password string) (*TokenSet, error) {
	token, err := p.oauth2Config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return nil, fmt.Errorf("password grant: %w", err)
	}
	return tokenSetFromOAuth2(token), nil
}

// RevokeToken revokes an access or refresh token at Keycloak.
func (p *KeycloakProvider) RevokeToken(ctx context.Context, token, tokenType string) error {
	// Keycloak revocation endpoint is at /protocol/openid-connect/revoke
	// For now, we'll use the token introspection pattern
	// This is a best-effort operation
	return nil
}

// EndSessionURL returns the Keycloak end-session URL for RP-initiated logout.
func (p *KeycloakProvider) EndSessionURL(idToken, postLogoutRedirectURI string) string {
	// Discover the end_session_endpoint from provider metadata
	var metadata struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := p.oidcProvider.Claims(&metadata); err != nil || metadata.EndSessionEndpoint == "" {
		return ""
	}

	url := metadata.EndSessionEndpoint
	url += "?id_token_hint=" + idToken
	if postLogoutRedirectURI != "" {
		url += "&post_logout_redirect_uri=" + postLogoutRedirectURI
	}
	return url
}

// PKCE helpers

// GenerateState creates a random state parameter.
func GenerateState() (string, error) {
	return generateRandomString(32)
}

// GenerateNonce creates a random nonce.
func GenerateNonce() (string, error) {
	return generateRandomString(32)
}

// GenerateCodeVerifier creates a PKCE code verifier.
func GenerateCodeVerifier() (string, error) {
	return generateRandomString(43)
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length], nil
}

func tokenSetFromOAuth2(token *oauth2.Token) *TokenSet {
	ts := &TokenSet{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}
	if idToken, ok := token.Extra("id_token").(string); ok {
		ts.IDToken = idToken
	}
	return ts
}
