package handlers

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestDecodeJWTPayload(t *testing.T) {
	// Build a valid JWT with known claims
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"sub": "user-123",
		"email": "test@example.com",
		"tenant_id": "tenant-1",
		"tenant_slug": "demo",
		"preferred_username": "testuser",
		"platform_owner": "true"
	}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesignature"))
	token := header + "." + payload + "." + sig

	claims := decodeJWTPayload(token)
	if claims == nil {
		t.Fatal("expected non-nil claims")
	}

	tests := []struct {
		key  string
		want string
	}{
		{"sub", "user-123"},
		{"email", "test@example.com"},
		{"tenant_id", "tenant-1"},
		{"tenant_slug", "demo"},
		{"preferred_username", "testuser"},
		{"platform_owner", "true"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got, _ := claims[tt.key].(string)
			if got != tt.want {
				t.Errorf("claims[%q] = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestDecodeJWTPayload_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"one part", "abc"},
		{"two parts", "abc.def"},
		{"invalid base64", "abc.!!!invalid!!!.xyz"},
		{"invalid json", "abc." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".xyz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := decodeJWTPayload(tt.token)
			if claims != nil {
				t.Errorf("expected nil for invalid token %q", tt.token)
			}
		})
	}
}

func TestDecodeJWTPayload_NestedClaims(t *testing.T) {
	claims := map[string]interface{}{
		"sub":       "user-456",
		"tenant_id": "t-1",
		"realm_access": map[string]interface{}{
			"roles": []string{"admin", "user"},
		},
	}
	payloadBytes, _ := json.Marshal(claims)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	token := header + "." + payload + "." + sig

	result := decodeJWTPayload(token)
	if result == nil {
		t.Fatal("expected non-nil claims")
	}
	if result["sub"] != "user-456" {
		t.Errorf("sub = %v, want user-456", result["sub"])
	}
	ra, ok := result["realm_access"].(map[string]interface{})
	if !ok {
		t.Fatal("realm_access should be a map")
	}
	if ra["roles"] == nil {
		t.Error("realm_access.roles should exist")
	}
}
