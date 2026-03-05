package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
)

const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestConfig() *config.Config {
	return &config.Config{
		Port:                "8080",
		Environment:         "test",
		CookieEncryptionKey: testKey,
		SessionMaxAge:       24 * time.Hour,
		PlatformDomain:      "tesserix.app",
		CSRFSecret:          testKey,
	}
}

func newTestApp() *config.AppConfig {
	return &config.AppConfig{
		Name:          "tesserix-home",
		SessionCookie: "th_session",
		PostLoginURL:  "/dashboard",
		PostLogoutURL: "/",
		CallbackPath:  "/auth/callback",
		AuthContext:    "staff",
	}
}

func TestAuthHandler_Session_Unauthenticated(t *testing.T) {
	cfg := newTestConfig()
	h := &AuthHandler{
		cfg:      cfg,
		sessions: session.NewCookieStore(testKey, 24*time.Hour, false),
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/auth/session", nil)

	h.Session(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["authenticated"] != false {
		t.Error("unauthenticated session should return authenticated=false")
	}
}

func TestAuthHandler_Session_Authenticated(t *testing.T) {
	cfg := newTestConfig()
	store := session.NewCookieStore(testKey, 24*time.Hour, false)
	h := &AuthHandler{cfg: cfg, sessions: store}

	sess := &session.Session{
		UserID:      "user-123",
		Email:       "test@example.com",
		TenantID:    "tenant-456",
		AuthContext:  "staff",
		CSRFToken:   "csrf-token",
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/auth/session", nil)
	c.Set(middleware.ContextKeySession, sess)

	h.Session(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["authenticated"] != true {
		t.Error("should be authenticated")
	}
	if resp["userId"] != "user-123" {
		t.Errorf("userId = %v, want user-123", resp["userId"])
	}
	if resp["email"] != "test@example.com" {
		t.Errorf("email = %v, want test@example.com", resp["email"])
	}
	if resp["csrfToken"] != "csrf-token" {
		t.Errorf("csrfToken = %v, want csrf-token", resp["csrfToken"])
	}
	// Should NOT expose tokens
	if _, ok := resp["accessToken"]; ok {
		t.Error("should not expose accessToken in session response")
	}
}

func TestAuthHandler_CSRFToken_NoSession(t *testing.T) {
	h := &AuthHandler{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/auth/csrf-token", nil)

	h.CSRFToken(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthHandler_CSRFToken_WithSession(t *testing.T) {
	h := &AuthHandler{}

	sess := &session.Session{CSRFToken: "my-csrf-token"}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/auth/csrf-token", nil)
	c.Set(middleware.ContextKeySession, sess)

	h.CSRFToken(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["csrfToken"] != "my-csrf-token" {
		t.Errorf("csrfToken = %v, want my-csrf-token", resp["csrfToken"])
	}
}

func TestAuthHandler_Logout_ClearsCookie(t *testing.T) {
	cfg := newTestConfig()
	store := session.NewCookieStore(testKey, 24*time.Hour, false)
	ephemeral := session.NewEphemeralStore()
	h := &AuthHandler{
		cfg:       cfg,
		sessions:  store,
		ephemeral: ephemeral,
		events:    nil, // events publisher is nil-safe
	}

	app := newTestApp()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/auth/logout", nil)
	c.Request.Host = "tesserix.app"
	c.Set(middleware.ContextKeyApp, app)

	h.Logout(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Check that a clearing cookie was set
	found := false
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "th_session" && cookie.MaxAge < 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie to be cleared")
	}
}

func TestAuthHandler_Refresh_NoSession(t *testing.T) {
	h := &AuthHandler{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/auth/refresh", nil)
	c.Set(middleware.ContextKeyApp, newTestApp())

	h.Refresh(c)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthHandler_Login_NoApp(t *testing.T) {
	h := &AuthHandler{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/auth/login", nil)
	// No app in context

	h.Login(c)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown app, got %d", w.Code)
	}
}

func TestGenerateRandom(t *testing.T) {
	r1 := generateRandom(32)
	r2 := generateRandom(32)

	if r1 == "" || r2 == "" {
		t.Error("random string should not be empty")
	}
	if r1 == r2 {
		t.Error("two random strings should be different")
	}
	if len(r1) < 32 {
		t.Errorf("random string too short: %d chars", len(r1))
	}
}
