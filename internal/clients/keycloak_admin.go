package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/tesserix/go-shared/httpclient"
)

// KeycloakAdminClient provides access to Keycloak's Admin REST API.
type KeycloakAdminClient struct {
	baseURL      string
	realm        string
	clientID     string
	clientSecret string
	httpClient   *http.Client

	mu           sync.Mutex
	accessToken  string
	tokenExpiry  time.Time
}

// NewKeycloakAdminClient creates a new Keycloak admin client.
func NewKeycloakAdminClient(baseURL, realm, clientID, clientSecret string) *KeycloakAdminClient {
	return &KeycloakAdminClient{
		baseURL:      baseURL,
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   httpclient.NewClientWithProfile(httpclient.ProfileDefault),
	}
}

// KeycloakUser represents a Keycloak user.
type KeycloakUser struct {
	ID            string            `json:"id"`
	Username      string            `json:"username"`
	Email         string            `json:"email"`
	FirstName     string            `json:"firstName"`
	LastName      string            `json:"lastName"`
	Enabled       bool              `json:"enabled"`
	EmailVerified bool              `json:"emailVerified"`
	Attributes    map[string][]string `json:"attributes,omitempty"`
}

// GetUserByEmail finds a user by email in the realm.
func (k *KeycloakAdminClient) GetUserByEmail(ctx context.Context, email string) (*KeycloakUser, error) {
	token, err := k.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/users?email=%s&exact=true",
		k.baseURL, k.realm, url.QueryEscape(email))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak get user: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak get user: %d %s", resp.StatusCode, string(body))
	}

	var users []KeycloakUser
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("parse keycloak users: %w", err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("user not found: %s", email)
	}
	return &users[0], nil
}

// UpdateUserAttributes updates custom attributes on a Keycloak user.
func (k *KeycloakAdminClient) UpdateUserAttributes(ctx context.Context, userID string, attrs map[string][]string) error {
	token, err := k.getAdminToken(ctx)
	if err != nil {
		return err
	}

	body := map[string]interface{}{"attributes": attrs}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/users/%s", k.baseURL, k.realm, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("keycloak update user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("keycloak update user: %d %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// getAdminToken obtains or reuses a service account token for admin API access.
func (k *KeycloakAdminClient) getAdminToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Reuse cached token if still valid (with 30s buffer)
	if k.accessToken != "" && time.Now().Add(30*time.Second).Before(k.tokenExpiry) {
		return k.accessToken, nil
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", k.baseURL, k.realm)
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {k.clientID},
		"client_secret": {k.clientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak token: %d %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}

	k.accessToken = tokenResp.AccessToken
	k.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return k.accessToken, nil
}
