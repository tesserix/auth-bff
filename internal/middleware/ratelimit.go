package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter provides in-memory per-IP rate limiting.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
	rpm     int
}

type rateLimitEntry struct {
	count    int
	windowAt time.Time
}

// NewRateLimiter creates a new in-memory rate limiter.
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	rl := &RateLimiter{
		entries: make(map[string]*rateLimitEntry),
		rpm:     requestsPerMinute,
	}
	// Cleanup goroutine
	go rl.cleanup()
	return rl
}

// Middleware returns a Gin middleware that rate-limits by client IP.
// Internal service-to-service paths are exempt from rate limiting.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		// Skip rate limiting for internal calls, session checks, and health probes
		if strings.HasPrefix(path, "/internal/") ||
			path == "/auth/session" ||
			path == "/auth/csrf-token" ||
			path == "/health" ||
			path == "/ready" {
			c.Next()
			return
		}

		ip := clientIP(c)
		allowed, remaining, resetAt := rl.allow(ip)

		c.Header("X-RateLimit-Limit", strconv.Itoa(rl.rpm))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))

		if !allowed {
			retryAfter := int(time.Until(resetAt).Seconds()) + 1
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"success":    false,
				"error":      "RATE_LIMIT_EXCEEDED",
				"message":    "Too many requests, please try again later",
				"retryAfter": retryAfter,
			})
			return
		}

		c.Next()
	}
}

func (rl *RateLimiter) allow(key string) (bool, int, time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowEnd := now.Truncate(time.Minute).Add(time.Minute)

	entry, exists := rl.entries[key]
	if !exists || now.After(entry.windowAt) {
		rl.entries[key] = &rateLimitEntry{count: 1, windowAt: windowEnd}
		return true, rl.rpm - 1, windowEnd
	}

	entry.count++
	remaining := rl.rpm - entry.count
	if remaining < 0 {
		remaining = 0
	}
	return entry.count <= rl.rpm, remaining, entry.windowAt
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, entry := range rl.entries {
			if now.After(entry.windowAt) {
				delete(rl.entries, key)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the real client IP with proxy awareness.
func clientIP(c *gin.Context) string {
	// Cloudflare
	if ip := c.GetHeader("cf-connecting-ip"); ip != "" {
		return ip
	}
	if ip := c.GetHeader("x-real-ip"); ip != "" {
		return ip
	}
	return c.ClientIP()
}
