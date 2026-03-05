// Package session provides encrypted cookie-based session management.
// Sessions are stored entirely in AES-256-GCM encrypted HTTP-only cookies.
// No server-side session storage (Redis/DB) is required.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tesserix/auth-bff/internal/crypto"
)

var (
	ErrNotFound     = errors.New("session not found")
	ErrExpired      = errors.New("session expired")
	ErrInvalidToken = errors.New("invalid session token")
)

// CookieStore manages encrypted cookie-based sessions.
type CookieStore struct {
	encryptionKey string // AES-256 key (hex)
	maxAge        time.Duration
	secure        bool // HTTPS-only cookies
	domain        string
}

// NewCookieStore creates a new encrypted cookie session store.
func NewCookieStore(encryptionKey string, maxAge time.Duration, secure bool) *CookieStore {
	return &CookieStore{
		encryptionKey: encryptionKey,
		maxAge:        maxAge,
		secure:        secure,
	}
}

// Session represents an authenticated user session.
type Session struct {
	UserID       string `json:"uid"`
	Email        string `json:"email"`
	TenantID     string `json:"tid"`
	TenantSlug   string `json:"ts"`
	AuthContext   string `json:"ctx"`  // "staff" or "customer"
	AccessToken  string `json:"at"`
	IDToken      string `json:"idt"`
	RefreshToken string `json:"rt"`
	ExpiresAt    int64  `json:"exp"`
	CSRFToken    string `json:"csrf"`
	AppName      string `json:"app"`
	IssuedAt     int64  `json:"iat"`
}

// IsExpired returns true if the session tokens have expired.
func (s *Session) IsExpired() bool {
	return time.Now().Unix() > s.ExpiresAt
}

// Save encrypts the session and writes it as an HTTP-only cookie.
func (cs *CookieStore) Save(c *gin.Context, cookieName, cookieDomain string, sess *Session) error {
	sess.IssuedAt = time.Now().Unix()

	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("session: marshal: %w", err)
	}

	encrypted, err := crypto.EncryptAESGCM(data, cs.encryptionKey)
	if err != nil {
		return fmt.Errorf("session: encrypt: %w", err)
	}

	maxAgeSeconds := int(cs.maxAge.Seconds())
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cookieName, encrypted, maxAgeSeconds, "/", cookieDomain, cs.secure, true)
	return nil
}

// Load reads and decrypts the session from the cookie.
func (cs *CookieStore) Load(c *gin.Context, cookieName string) (*Session, error) {
	encrypted, err := c.Cookie(cookieName)
	if err != nil || encrypted == "" {
		return nil, ErrNotFound
	}

	data, err := crypto.DecryptAESGCM(encrypted, cs.encryptionKey)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, ErrInvalidToken
	}

	// Check session age
	maxAge := time.Duration(cs.maxAge.Seconds()) * time.Second
	if time.Since(time.Unix(sess.IssuedAt, 0)) > maxAge {
		return nil, ErrExpired
	}

	return &sess, nil
}

// LoadFromValue decrypts a raw cookie value and returns the session.
// Used by internal endpoints that receive the cookie value directly (not from HTTP request).
func (cs *CookieStore) LoadFromValue(encrypted string) (*Session, error) {
	if encrypted == "" {
		return nil, ErrNotFound
	}

	data, err := crypto.DecryptAESGCM(encrypted, cs.encryptionKey)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, ErrInvalidToken
	}

	maxAge := time.Duration(cs.maxAge.Seconds()) * time.Second
	if time.Since(time.Unix(sess.IssuedAt, 0)) > maxAge {
		return nil, ErrExpired
	}

	return &sess, nil
}

// Clear removes the session cookie.
func (cs *CookieStore) Clear(c *gin.Context, cookieName, cookieDomain string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cookieName, "", -1, "/", cookieDomain, cs.secure, true)
}
