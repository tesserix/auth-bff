package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(10) // 10 RPM

	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Request.RemoteAddr = "1.2.3.4:1234"

		rl.Middleware()(c)

		if w.Code == http.StatusTooManyRequests {
			t.Errorf("request %d should have been allowed", i+1)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(5)

	for i := 0; i < 6; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Request.RemoteAddr = "1.2.3.4:1234"

		rl.Middleware()(c)

		if i < 5 && w.Code == http.StatusTooManyRequests {
			t.Errorf("request %d should have been allowed", i+1)
		}
		if i == 5 && w.Code != http.StatusTooManyRequests {
			t.Errorf("request %d should have been blocked, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(2)

	// IP 1: 2 requests (at limit)
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Request.RemoteAddr = "1.1.1.1:1234"
		rl.Middleware()(c)
	}

	// IP 2: should still be allowed
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.RemoteAddr = "2.2.2.2:1234"
	rl.Middleware()(c)

	if w.Code == http.StatusTooManyRequests {
		t.Error("different IP should not be rate limited")
	}
}

func TestRateLimiter_Headers(t *testing.T) {
	rl := NewRateLimiter(10)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.RemoteAddr = "1.2.3.4:1234"

	rl.Middleware()(c)

	if w.Header().Get("X-RateLimit-Limit") != "10" {
		t.Errorf("expected X-RateLimit-Limit=10, got %s", w.Header().Get("X-RateLimit-Limit"))
	}
	if w.Header().Get("X-RateLimit-Remaining") != "9" {
		t.Errorf("expected X-RateLimit-Remaining=9, got %s", w.Header().Get("X-RateLimit-Remaining"))
	}
	if w.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("expected X-RateLimit-Reset to be set")
	}
}

func TestRateLimiter_CloudflareHeader(t *testing.T) {
	rl := NewRateLimiter(2)

	// Use up limit for CF IP
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Request.Header.Set("cf-connecting-ip", "5.5.5.5")
		c.Request.RemoteAddr = "10.0.0.1:1234" // different RemoteAddr
		rl.Middleware()(c)
	}

	// Third request from same CF IP should be blocked
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.Header.Set("cf-connecting-ip", "5.5.5.5")
	c.Request.RemoteAddr = "10.0.0.2:1234" // different proxy IP
	rl.Middleware()(c)

	if w.Code != http.StatusTooManyRequests {
		t.Error("should rate limit by cf-connecting-ip, not RemoteAddr")
	}
}
