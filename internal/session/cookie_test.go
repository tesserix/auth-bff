package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// testEncryptionKey is a 64-char hex string (32 bytes) for AES-256.
const testEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func init() {
	gin.SetMode(gin.TestMode)
}

func TestCookieStore_SaveAndLoad(t *testing.T) {
	store := NewCookieStore(testEncryptionKey, 24*time.Hour, false)

	sess := &Session{
		UserID:      "user-123",
		Email:       "test@example.com",
		TenantID:    "tenant-456",
		TenantSlug:  "acme",
		AuthContext:  "staff",
		AccessToken: "at_token",
		IDToken:     "id_token",
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
		CSRFToken:   "csrf-abc",
		AppName:     "tesserix-home",
	}

	// Save session via a gin context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	if err := store.Save(c, "test_session", "", sess); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Extract cookie from response
	resp := w.Result()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie set")
	}

	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "test_session" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("test_session cookie not found")
	}

	// Verify cookie properties
	if !sessionCookie.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}

	// Load session from cookie
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest("GET", "/", nil)
	c2.Request.AddCookie(sessionCookie)

	loaded, err := store.Load(c2, "test_session")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.UserID != sess.UserID {
		t.Errorf("UserID = %q, want %q", loaded.UserID, sess.UserID)
	}
	if loaded.Email != sess.Email {
		t.Errorf("Email = %q, want %q", loaded.Email, sess.Email)
	}
	if loaded.TenantID != sess.TenantID {
		t.Errorf("TenantID = %q, want %q", loaded.TenantID, sess.TenantID)
	}
	if loaded.CSRFToken != sess.CSRFToken {
		t.Errorf("CSRFToken = %q, want %q", loaded.CSRFToken, sess.CSRFToken)
	}
	if loaded.AccessToken != sess.AccessToken {
		t.Errorf("AccessToken = %q, want %q", loaded.AccessToken, sess.AccessToken)
	}
	if loaded.IssuedAt == 0 {
		t.Error("IssuedAt should be set")
	}
}

func TestCookieStore_Load_NoCookie(t *testing.T) {
	store := NewCookieStore(testEncryptionKey, 24*time.Hour, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	_, err := store.Load(c, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCookieStore_Load_TamperedCookie(t *testing.T) {
	store := NewCookieStore(testEncryptionKey, 24*time.Hour, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.AddCookie(&http.Cookie{Name: "test_session", Value: "tampered-value"})

	_, err := store.Load(c, "test_session")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestCookieStore_Load_ExpiredSession(t *testing.T) {
	store := NewCookieStore(testEncryptionKey, 1*time.Millisecond, false) // very short TTL

	sess := &Session{
		UserID: "user-123",
		Email:  "test@example.com",
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	if err := store.Save(c, "test_session", "", sess); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(5 * time.Millisecond)

	// Load from cookie
	resp := w.Result()
	var sessionCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "test_session" {
			sessionCookie = cookie
			break
		}
	}

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest("GET", "/", nil)
	c2.Request.AddCookie(sessionCookie)

	_, err := store.Load(c2, "test_session")
	if err != ErrExpired {
		t.Errorf("expected ErrExpired, got %v", err)
	}
}

func TestCookieStore_Clear(t *testing.T) {
	store := NewCookieStore(testEncryptionKey, 24*time.Hour, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)

	store.Clear(c, "test_session", "")

	resp := w.Result()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "test_session" {
			if cookie.MaxAge >= 0 {
				t.Error("cleared cookie should have negative MaxAge")
			}
			return
		}
	}
	t.Error("no clearing cookie set")
}

func TestCookieStore_WrongKey(t *testing.T) {
	key1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	key2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	store1 := NewCookieStore(key1, 24*time.Hour, false)
	store2 := NewCookieStore(key2, 24*time.Hour, false)

	sess := &Session{UserID: "user-123", Email: "test@example.com"}

	// Save with key1
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	store1.Save(c, "test_session", "", sess)

	var cookie *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "test_session" {
			cookie = ck
			break
		}
	}

	// Load with key2 should fail
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest("GET", "/", nil)
	c2.Request.AddCookie(cookie)

	_, err := store2.Load(c2, "test_session")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestSession_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt int64
		want      bool
	}{
		{"future", time.Now().Add(time.Hour).Unix(), false},
		{"past", time.Now().Add(-time.Hour).Unix(), true},
		{"just_expired", time.Now().Add(-time.Second).Unix(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{ExpiresAt: tt.expiresAt}
			if got := s.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}
