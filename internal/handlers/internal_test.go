package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/session"
	"github.com/tesserix/go-shared/logger"
)

func TestInternalHandler_ValidateSession(t *testing.T) {
	store := newMockStore()
	store.CreateSession(nil, &session.Session{
		ID:         "sess-1",
		UserID:     "user-1",
		Email:      "test@example.com",
		TenantID:   "tenant-1",
		TenantSlug: "demo",
		ClientType: "internal",
		ExpiresAt:  9999999999,
	})

	cfg := &config.Config{InternalServiceKey: "test-key"}
	log := logger.New(logger.DefaultConfig("test"))
	handler := NewInternalHandler(cfg, store, log)

	router := setupRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name       string
		body       map[string]string
		serviceKey string
		wantStatus int
		wantValid  bool
	}{
		{
			name:       "valid session",
			body:       map[string]string{"sessionId": "sess-1"},
			serviceKey: "test-key",
			wantStatus: http.StatusOK,
			wantValid:  true,
		},
		{
			name:       "invalid session",
			body:       map[string]string{"sessionId": "nonexistent"},
			serviceKey: "test-key",
			wantStatus: http.StatusOK,
			wantValid:  false,
		},
		{
			name:       "wrong service key",
			body:       map[string]string{"sessionId": "sess-1"},
			serviceKey: "wrong-key",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing session id",
			body:       map[string]string{},
			serviceKey: "test-key",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/internal/validate-session", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Internal-Service-Key", tt.serviceKey)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			if tt.wantStatus == http.StatusOK {
				var resp map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &resp)
				if valid, ok := resp["valid"].(bool); ok && valid != tt.wantValid {
					t.Errorf("valid = %v, want %v", valid, tt.wantValid)
				}
			}
		})
	}
}

func TestInternalHandler_ExchangeToken(t *testing.T) {
	store := newMockStore()
	store.CreateSession(nil, &session.Session{
		ID:          "sess-1",
		UserID:      "user-1",
		TenantID:    "tenant-1",
		AccessToken: "access-token-here",
		ExpiresAt:   9999999999,
	})

	cfg := &config.Config{InternalServiceKey: ""}
	log := logger.New(logger.DefaultConfig("test"))
	handler := NewInternalHandler(cfg, store, log)

	router := setupRouter()
	handler.RegisterRoutes(router)

	body, _ := json.Marshal(map[string]string{"sessionId": "sess-1"})
	req := httptest.NewRequest(http.MethodPost, "/internal/exchange-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["accessToken"] != "access-token-here" {
		t.Errorf("accessToken = %v, want access-token-here", resp["accessToken"])
	}
}

func TestInternalHandler_ValidateWSTicket(t *testing.T) {
	store := newMockStore()
	cfg := &config.Config{}
	log := logger.New(logger.DefaultConfig("test"))
	handler := NewInternalHandler(cfg, store, log)

	router := setupRouter()
	handler.RegisterRoutes(router)

	// No ticket saved — should return invalid
	body, _ := json.Marshal(map[string]string{"ticket": "nonexistent"})
	req := httptest.NewRequest(http.MethodPost, "/internal/validate-ws-ticket", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["valid"] != false {
		t.Errorf("valid = %v, want false", resp["valid"])
	}
}

func TestInternalHandler_NoKeyRequired_Development(t *testing.T) {
	store := newMockStore()
	store.CreateSession(nil, &session.Session{
		ID:     "sess-1",
		UserID: "user-1",
	})

	// Empty InternalServiceKey = no auth required (development)
	cfg := &config.Config{InternalServiceKey: ""}
	log := logger.New(logger.DefaultConfig("test"))
	handler := NewInternalHandler(cfg, store, log)

	router := setupRouter()
	handler.RegisterRoutes(router)

	body, _ := json.Marshal(map[string]string{"sessionId": "sess-1"})
	req := httptest.NewRequest(http.MethodPost, "/internal/validate-session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No service key header
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (no key required in dev)", w.Code)
	}
}
