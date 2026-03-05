package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/session"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestGetEffectiveHost(t *testing.T) {
	tests := []struct {
		name            string
		xForwardedHost  string
		requestHost     string
		want            string
	}{
		{"forwarded header", "demo-admin.tesserix.app", "internal:8080", "demo-admin.tesserix.app"},
		{"comma separated", "demo.tesserix.app, 10.0.0.1", "internal:8080", "demo.tesserix.app"},
		{"no forwarded", "", "localhost:8080", "localhost:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			var got string
			r.GET("/test", func(c *gin.Context) {
				got = GetEffectiveHost(c)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.xForwardedHost != "" {
				req.Header.Set("x-forwarded-host", tt.xForwardedHost)
			}
			req.Host = tt.requestHost
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetCookieDomain(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		productDomain  string
		platformDomain string
		want           string
	}{
		{"product subdomain", "demo-admin.tesserix.app", "tesserix.app", "tesserix.app", ".tesserix.app"},
		{"product root", "tesserix.app", "tesserix.app", "tesserix.app", ".tesserix.app"},
		{"platform fallback", "www.tesserix.app", "mark8ly.com", "tesserix.app", ".tesserix.app"},
		{"localhost", "localhost:3000", "tesserix.app", "tesserix.app", ""},
		{"localhost no port", "localhost", "tesserix.app", "tesserix.app", ""},
		{"custom domain", "myshop.com", "tesserix.app", "tesserix.app", ".myshop.com"},
		{"custom domain www", "www.myshop.com", "tesserix.app", "tesserix.app", ".myshop.com"},
		{"product domain match", "demo.mark8ly.com", "mark8ly.com", "tesserix.app", ".mark8ly.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &config.AppConfig{ProductDomain: tt.productDomain}
			got := GetCookieDomain(tt.host, app, tt.platformDomain)
			if got != tt.want {
				t.Errorf("GetCookieDomain(%q, {ProductDomain:%q}, %q) = %q, want %q",
					tt.host, tt.productDomain, tt.platformDomain, got, tt.want)
			}
		})
	}
}

func TestCSRFProtection_SafeMethods(t *testing.T) {
	r := gin.New()
	r.Use(CSRFProtection())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})
	r.OPTIONS("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		req := httptest.NewRequest(method, "/test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("%s /test = %d, want 200", method, w.Code)
		}
	}
}

func TestCSRFProtection_NoSession(t *testing.T) {
	r := gin.New()
	r.Use(CSRFProtection())
	r.POST("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// No session = CSRF check skipped
	if w.Code != http.StatusOK {
		t.Errorf("POST without session = %d, want 200", w.Code)
	}
}

func TestCSRFProtection_ValidToken(t *testing.T) {
	r := gin.New()

	// Inject session with CSRF token
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeySession, &session.Session{CSRFToken: "valid-csrf-token"})
		c.Next()
	})
	r.Use(CSRFProtection())
	r.POST("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-CSRF-Token", "valid-csrf-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("POST with valid CSRF = %d, want 200", w.Code)
	}
}

func TestCSRFProtection_InvalidToken(t *testing.T) {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeySession, &session.Session{CSRFToken: "valid-csrf-token"})
		c.Next()
	})
	r.Use(CSRFProtection())
	r.POST("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// Wrong token
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-CSRF-Token", "wrong-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("POST with invalid CSRF = %d, want 403", w.Code)
	}

	// Missing token
	req2 := httptest.NewRequest(http.MethodPost, "/test", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("POST with missing CSRF = %d, want 403", w2.Code)
	}
}

func TestRequireSession(t *testing.T) {
	r := gin.New()
	r.Use(RequireSession())
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// No session
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("no session = %d, want 401", w.Code)
	}

	// With session
	r2 := gin.New()
	r2.Use(func(c *gin.Context) {
		c.Set(ContextKeySession, &session.Session{UserID: "test"})
		c.Next()
	})
	r2.Use(RequireSession())
	r2.GET("/protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w2 := httptest.NewRecorder()
	r2.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("with session = %d, want 200", w2.Code)
	}
}

func TestGetSession_Nil(t *testing.T) {
	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		s := GetSession(c)
		if s != nil {
			c.JSON(500, gin.H{"error": "expected nil"})
			return
		}
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestGetApp(t *testing.T) {
	r := gin.New()

	app := &config.AppConfig{Name: "admin", SessionCookie: "bff_session"}
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeyApp, app)
		c.Next()
	})
	r.GET("/test", func(c *gin.Context) {
		a := GetApp(c)
		if a == nil || a.Name != "admin" {
			c.JSON(500, gin.H{"error": "wrong app"})
			return
		}
		c.JSON(200, gin.H{"app": a.Name})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(3) // 3 requests per minute
	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// First 3 requests succeed
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want 200", i+1, w.Code)
		}
	}

	// 4th request rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("4th request: status = %d, want 429", w.Code)
	}

	// Different IP succeeds
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "10.0.0.1:12345"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("different IP: status = %d, want 200", w2.Code)
	}
}

