package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
	"github.com/tesserix/go-shared/logger"
)

func testConfig() *config.Config {
	return &config.Config{
		Environment:    "development",
		PlatformDomain: "tesserix.app",
		SessionMaxAge:  86400,
		Apps: []config.AppConfig{
			{Name: "admin", SessionCookie: "bff_session", Realm: "internal", PostLoginURL: "/", PostLogoutURL: "/login", ProductDomain: "tesserix.app"},
			{Name: "storefront", SessionCookie: "bff_storefront_session", Realm: "customers", PostLoginURL: "/", PostLogoutURL: "/", ProductDomain: "tesserix.app"},
			{Name: "home", SessionCookie: "bff_home_session", Realm: "internal", PostLoginURL: "/", PostLogoutURL: "/login", ProductDomain: "tesserix.app"},
		},
	}
}

func testLogger() *logger.Logger {
	return logger.New(logger.Config{
		Level:       logger.LevelError,
		ServiceName: "test",
		Format:      "text",
	})
}

func TestAuthHandler_Session_Authenticated(t *testing.T) {
	store := newMockStore()
	sess := &session.Session{
		ID:         "sess-1",
		UserID:     "user-1",
		Email:      "test@example.com",
		TenantID:   "tenant-1",
		TenantSlug: "demo",
		ExpiresAt:  9999999999,
		CSRFToken:  "csrf-123",
		UserInfo: &session.UserInfo{
			Name:      "Test User",
			GivenName: "Test",
			FamilyName: "User",
			Roles:     []string{"admin"},
		},
	}
	store.CreateSession(nil, sess)

	cfg := testConfig()
	handler := NewAuthHandler(cfg, store, nil, testLogger())

	router := setupRouter()
	router.Use(func(c *gin.Context) {
		c.Set(middleware.ContextKeySession, sess)
		c.Next()
	})
	group := router.Group("")
	handler.RegisterRoutes(group)

	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["authenticated"] != true {
		t.Errorf("authenticated = %v, want true", resp["authenticated"])
	}
	if resp["csrfToken"] != "csrf-123" {
		t.Errorf("csrfToken = %v, want csrf-123", resp["csrfToken"])
	}

	user := resp["user"].(map[string]interface{})
	if user["id"] != "user-1" {
		t.Errorf("user.id = %v, want user-1", user["id"])
	}
	if user["email"] != "test@example.com" {
		t.Errorf("user.email = %v", user["email"])
	}
	if user["name"] != "Test User" {
		t.Errorf("user.name = %v", user["name"])
	}
}

func TestAuthHandler_Session_NotAuthenticated(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	handler := NewAuthHandler(cfg, store, nil, testLogger())

	router := setupRouter()
	group := router.Group("")
	handler.RegisterRoutes(group)

	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["authenticated"] != false {
		t.Errorf("authenticated = %v, want false", resp["authenticated"])
	}
}

func TestAuthHandler_CSRFToken_Authenticated(t *testing.T) {
	store := newMockStore()
	sess := &session.Session{ID: "sess-1", CSRFToken: "csrf-abc"}
	store.CreateSession(nil, sess)

	cfg := testConfig()
	handler := NewAuthHandler(cfg, store, nil, testLogger())

	router := setupRouter()
	router.Use(func(c *gin.Context) {
		c.Set(middleware.ContextKeySession, sess)
		c.Next()
	})
	group := router.Group("")
	handler.RegisterRoutes(group)

	req := httptest.NewRequest(http.MethodGet, "/auth/csrf-token", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["csrfToken"] != "csrf-abc" {
		t.Errorf("csrfToken = %v, want csrf-abc", resp["csrfToken"])
	}
}

func TestAuthHandler_CSRFToken_Unauthenticated(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	handler := NewAuthHandler(cfg, store, nil, testLogger())

	router := setupRouter()
	group := router.Group("")
	handler.RegisterRoutes(group)

	req := httptest.NewRequest(http.MethodGet, "/auth/csrf-token", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestSanitizeReturnTo(t *testing.T) {
	app := &config.AppConfig{Name: "admin"}

	tests := []struct {
		name   string
		input  string
		want   string
	}{
		{"relative path", "/dashboard", "/dashboard"},
		{"root", "/", "/"},
		{"deep path", "/admin/settings/profile", "/admin/settings/profile"},
		{"empty", "", ""},
		{"absolute url", "https://evil.com/steal", ""},
		{"protocol relative", "//evil.com", ""},
		{"no leading slash", "dashboard", ""},
		{"javascript", "javascript:alert(1)", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeReturnTo(tt.input, app)
			if got != tt.want {
				t.Errorf("sanitizeReturnTo(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractTenantSlug(t *testing.T) {
	tests := []struct {
		host          string
		productDomain string
		want          string
	}{
		{"demo-admin.tesserix.app", "tesserix.app", "demo"},
		{"mystore-admin.tesserix.app", "tesserix.app", "mystore"},
		{"demo.tesserix.app", "tesserix.app", "demo"},
		{"www.tesserix.app", "tesserix.app", ""}, // known subdomain
		{"api.tesserix.app", "tesserix.app", ""},  // known subdomain
		{"dev.tesserix.app", "tesserix.app", ""},  // known subdomain
		{"tesserix.app", "tesserix.app", ""},       // root
		{"localhost:3000", "tesserix.app", ""},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			app := &config.AppConfig{ProductDomain: tt.productDomain}
			got := extractTenantSlug(tt.host, app)
			if got != tt.want {
				t.Errorf("extractTenantSlug(%q, {ProductDomain:%q}) = %q, want %q", tt.host, tt.productDomain, got, tt.want)
			}
		})
	}
}

func TestBuildUserInfo(t *testing.T) {
	claims := map[string]interface{}{
		"sub":                "user-123",
		"email":              "test@example.com",
		"email_verified":     true,
		"name":               "Test User",
		"given_name":         "Test",
		"family_name":        "User",
		"preferred_username": "testuser",
		"tenant_id":          "tenant-1",
		"platform_owner":     "true",
		"roles":              []interface{}{"admin", "editor"},
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"manage-account", "view-profile"},
		},
	}

	info := buildUserInfo(claims)
	if info == nil {
		t.Fatal("expected non-nil UserInfo")
	}

	if info.Sub != "user-123" {
		t.Errorf("Sub = %q", info.Sub)
	}
	if info.Email != "test@example.com" {
		t.Errorf("Email = %q", info.Email)
	}
	if !info.EmailVerified {
		t.Error("EmailVerified should be true")
	}
	if info.Name != "Test User" {
		t.Errorf("Name = %q", info.Name)
	}
	if !info.IsPlatformOwner {
		t.Error("IsPlatformOwner should be true")
	}
	if len(info.Roles) != 2 {
		t.Errorf("Roles len = %d, want 2", len(info.Roles))
	}
	if len(info.RealmAccessRoles) != 2 {
		t.Errorf("RealmAccessRoles len = %d, want 2", len(info.RealmAccessRoles))
	}
}

func TestBuildUserInfo_Nil(t *testing.T) {
	info := buildUserInfo(nil)
	if info != nil {
		t.Error("expected nil for nil claims")
	}
}

func TestMergeRoles(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want int
	}{
		{"no overlap", []string{"admin"}, []string{"editor"}, 2},
		{"full overlap", []string{"admin"}, []string{"admin"}, 1},
		{"partial overlap", []string{"admin", "editor"}, []string{"editor", "viewer"}, 3},
		{"empty a", nil, []string{"admin"}, 1},
		{"empty b", []string{"admin"}, nil, 1},
		{"both empty", nil, nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeRoles(tt.a, tt.b)
			if len(got) != tt.want {
				t.Errorf("mergeRoles len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestClientTypeForRealm(t *testing.T) {
	if got := clientTypeForRealm("customers"); got != "customer" {
		t.Errorf("customers realm = %q, want customer", got)
	}
	if got := clientTypeForRealm("internal"); got != "internal" {
		t.Errorf("internal realm = %q, want internal", got)
	}
	if got := clientTypeForRealm("other"); got != "internal" {
		t.Errorf("other realm = %q, want internal", got)
	}
}
