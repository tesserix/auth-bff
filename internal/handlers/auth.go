package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/events"
	"github.com/tesserix/auth-bff/internal/gip"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
)

// AuthHandler handles OIDC authentication flows via Google Identity Platform.
type AuthHandler struct {
	cfg       *config.Config
	gip       *gip.Client
	sessions  *session.CookieStore
	ephemeral *session.EphemeralStore
	events    *events.Publisher
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(cfg *config.Config, gipClient *gip.Client, sessions *session.CookieStore, ephemeral *session.EphemeralStore, events *events.Publisher) *AuthHandler {
	return &AuthHandler{
		cfg:       cfg,
		gip:       gipClient,
		sessions:  sessions,
		ephemeral: ephemeral,
		events:    events,
	}
}

// RegisterRoutes registers auth endpoints.
func (h *AuthHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.GET("/auth/login", h.Login)
	r.GET("/auth/callback", h.Callback)
	r.POST("/auth/logout", h.Logout)
	r.GET("/auth/session", h.Session)
	r.POST("/auth/refresh", h.Refresh)
	r.GET("/auth/csrf-token", h.CSRFToken)
}

// authFlowState is stored in the ephemeral store during the OIDC flow.
type authFlowState struct {
	Nonce        string `json:"n"`
	CodeVerifier string `json:"cv"`
	ReturnTo     string `json:"rt"`
	AppName      string `json:"app"`
}

// Login initiates the OIDC authorization flow with PKCE.
func (h *AuthHandler) Login(c *gin.Context) {
	app := middleware.GetApp(c)
	if app == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UNKNOWN_APP"})
		return
	}

	state := uuid.New().String()
	nonce := uuid.New().String()
	codeVerifier := generateRandom(64)
	returnTo := c.Query("return_to")
	if returnTo == "" {
		returnTo = app.PostLoginURL
	}

	// Build callback URL
	host := middleware.GetEffectiveHost(c)
	scheme := "https"
	if h.cfg.IsDevelopment() {
		scheme = "http"
	}
	redirectURI := fmt.Sprintf("%s://%s%s", scheme, host, app.CallbackPath)

	authURL, err := h.gip.AuthURL(app, state, nonce, codeVerifier, redirectURI)
	if err != nil {
		slog.Error("auth: generate auth url", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AUTH_INIT_FAILED"})
		return
	}

	// Store flow state (10 min TTL)
	flowState := authFlowState{
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		ReturnTo:     returnTo,
		AppName:      app.Name,
	}
	data, _ := json.Marshal(flowState)
	h.ephemeral.Set("authflow:"+state, data, 10*time.Minute)

	c.Redirect(http.StatusFound, authURL)
}

// Callback handles the OIDC callback after user authentication.
func (h *AuthHandler) Callback(c *gin.Context) {
	app := middleware.GetApp(c)
	if app == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UNKNOWN_APP"})
		return
	}

	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		errMsg := c.Query("error_description")
		if errMsg == "" {
			errMsg = c.Query("error")
		}
		slog.Warn("auth: callback missing code/state", "error", errMsg)
		c.JSON(http.StatusBadRequest, gin.H{"error": "AUTH_CALLBACK_FAILED", "message": errMsg})
		return
	}

	// Consume flow state (single-use)
	flowData, ok := h.ephemeral.Consume("authflow:" + state)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_STATE"})
		return
	}

	var flowState authFlowState
	if err := json.Unmarshal(flowData, &flowState); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_STATE"})
		return
	}

	// Build redirect URI (must match what was sent to /authorize)
	host := middleware.GetEffectiveHost(c)
	scheme := "https"
	if h.cfg.IsDevelopment() {
		scheme = "http"
	}
	redirectURI := fmt.Sprintf("%s://%s%s", scheme, host, app.CallbackPath)

	// Exchange code for tokens
	tokens, err := h.gip.Exchange(c.Request.Context(), app, code, flowState.CodeVerifier, redirectURI)
	if err != nil {
		slog.Error("auth: token exchange failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TOKEN_EXCHANGE_FAILED"})
		return
	}

	// Verify ID token and extract claims
	claims, err := h.gip.VerifyIDToken(c.Request.Context(), app, tokens.IDToken)
	if err != nil {
		slog.Error("auth: verify id token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TOKEN_VERIFICATION_FAILED"})
		return
	}

	// Create session
	csrfToken := uuid.New().String()
	sess := &session.Session{
		UserID:       claims.Subject,
		Email:        claims.Email,
		TenantID:     claims.TenantID,
		AuthContext:   app.AuthContext,
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt.Unix(),
		CSRFToken:    csrfToken,
		AppName:      app.Name,
	}

	cookieDomain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
	if err := h.sessions.Save(c, app.SessionCookie, cookieDomain, sess); err != nil {
		slog.Error("auth: save session", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SESSION_CREATE_FAILED"})
		return
	}

	// Publish audit event
	h.events.PublishLoginSuccess(c.Request.Context(), claims.TenantID, claims.Subject, claims.Email, c.ClientIP(), c.GetHeader("User-Agent"), "oidc")

	// Redirect to return URL
	returnTo := flowState.ReturnTo
	if returnTo == "" {
		returnTo = app.PostLoginURL
	}
	c.Redirect(http.StatusFound, returnTo)
}

// Logout clears the session.
func (h *AuthHandler) Logout(c *gin.Context) {
	app := middleware.GetApp(c)
	if app == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UNKNOWN_APP"})
		return
	}

	sess := middleware.GetSession(c)
	if sess != nil {
		h.events.PublishLogout(c.Request.Context(), sess.TenantID, sess.UserID, sess.Email)
	}

	host := middleware.GetEffectiveHost(c)
	cookieDomain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
	h.sessions.Clear(c, app.SessionCookie, cookieDomain)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// Session returns the current session info (without tokens).
func (h *AuthHandler) Session(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusOK, gin.H{"authenticated": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"userId":        sess.UserID,
		"email":         sess.Email,
		"tenantId":      sess.TenantID,
		"tenantSlug":    sess.TenantSlug,
		"authContext":   sess.AuthContext,
		"expiresAt":     sess.ExpiresAt,
		"csrfToken":     sess.CSRFToken,
	})
}

// Refresh refreshes the session tokens.
func (h *AuthHandler) Refresh(c *gin.Context) {
	app := middleware.GetApp(c)
	if app == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UNKNOWN_APP"})
		return
	}

	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}

	if sess.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO_REFRESH_TOKEN"})
		return
	}

	tokens, err := h.gip.Refresh(c.Request.Context(), app, sess.RefreshToken)
	if err != nil {
		slog.Warn("auth: refresh failed", "error", err, "user_id", sess.UserID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "REFRESH_FAILED"})
		return
	}

	sess.AccessToken = tokens.AccessToken
	if tokens.IDToken != "" {
		sess.IDToken = tokens.IDToken
	}
	if tokens.RefreshToken != "" {
		sess.RefreshToken = tokens.RefreshToken
	}
	sess.ExpiresAt = tokens.ExpiresAt.Unix()

	host := middleware.GetEffectiveHost(c)
	cookieDomain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
	if err := h.sessions.Save(c, app.SessionCookie, cookieDomain, sess); err != nil {
		slog.Error("auth: save refreshed session", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SESSION_SAVE_FAILED"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"expiresAt": sess.ExpiresAt,
	})
}

// CSRFToken returns the CSRF token for the current session.
func (h *AuthHandler) CSRFToken(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"csrfToken": sess.CSRFToken})
}

func generateRandom(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
