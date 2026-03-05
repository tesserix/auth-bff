package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/gip"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
)

// InternalHandler handles service-to-service requests.
// Other services call these endpoints to verify tokens or exchange session data.
type InternalHandler struct {
	cfg      *config.Config
	gip      *gip.Client
	sessions *session.CookieStore
}

// NewInternalHandler creates a new InternalHandler.
func NewInternalHandler(cfg *config.Config, gipClient *gip.Client, sessions *session.CookieStore) *InternalHandler {
	return &InternalHandler{cfg: cfg, gip: gipClient, sessions: sessions}
}

// RegisterRoutes registers internal endpoints.
func (h *InternalHandler) RegisterRoutes(r *gin.Engine) {
	internal := r.Group("/internal")
	internal.Use(h.requireServiceKey())

	internal.POST("/verify-token", h.VerifyToken)
	internal.POST("/session-exchange", h.SessionExchange)
}

// requireServiceKey validates the Authorization: Bearer <key> header.
func (h *InternalHandler) requireServiceKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.cfg.InternalServiceKey == "" {
			c.Next() // allow in development
			return
		}

		token := middleware.ExtractBearerToken(c)
		if token != h.cfg.InternalServiceKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "UNAUTHORIZED"})
			return
		}
		c.Next()
	}
}

// VerifyToken verifies a GIP ID token and returns user claims.
// Used by backend services to validate tokens from frontend requests.
func (h *InternalHandler) VerifyToken(c *gin.Context) {
	var req struct {
		IDToken string `json:"id_token" binding:"required"`
		AppName string `json:"app_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}

	// Resolve app config to get the right GIP provider
	app := middleware.GetAppByName(c, req.AppName)
	if app == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UNKNOWN_APP"})
		return
	}

	claims, err := h.gip.VerifyIDToken(c.Request.Context(), app, req.IDToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "INVALID_TOKEN"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":    true,
		"user_id":  claims.Subject,
		"email":    claims.Email,
		"name":     claims.Name,
		"tenant":   claims.TenantID,
	})
}

// SessionExchange decrypts a session cookie and returns the access token + user claims.
// Called by tesserix-home (Next.js server) to get tokens for backend service calls.
// Replaces the old /auth/token-exchange endpoint that used Redis session lookup.
func (h *InternalHandler) SessionExchange(c *gin.Context) {
	var req struct {
		CookieName  string `json:"cookie_name" binding:"required"`
		CookieValue string `json:"cookie_value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}

	sess, err := h.sessions.LoadFromValue(req.CookieValue)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_SESSION"})
		return
	}

	if sess.IsExpired() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "SESSION_EXPIRED"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": sess.AccessToken,
		"id_token":     sess.IDToken,
		"user_id":      sess.UserID,
		"email":        sess.Email,
		"tenant_id":    sess.TenantID,
		"tenant_slug":  sess.TenantSlug,
		"auth_context": sess.AuthContext,
		"expires_at":   sess.ExpiresAt,
	})
}
