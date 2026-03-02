package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/go-shared/logger"
	"github.com/tesserix/auth-bff/internal/session"
)

// InternalHandler handles service-to-service requests.
type InternalHandler struct {
	cfg    *config.Config
	store  session.Store
	logger *logger.Logger
}

// NewInternalHandler creates a new InternalHandler.
func NewInternalHandler(cfg *config.Config, store session.Store, logger *logger.Logger) *InternalHandler {
	return &InternalHandler{
		cfg:    cfg,
		store:  store,
		logger: logger,
	}
}

// RegisterRoutes registers internal endpoints.
func (h *InternalHandler) RegisterRoutes(r *gin.Engine) {
	internal := r.Group("/internal")
	internal.Use(h.requireInternalAuth())

	internal.POST("/validate-session", h.ValidateSession)
	internal.POST("/exchange-token", h.ExchangeToken)
	internal.POST("/validate-ws-ticket", h.ValidateWSTicket)
}

// requireInternalAuth validates the X-Internal-Service-Key header.
func (h *InternalHandler) requireInternalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.cfg.InternalServiceKey == "" {
			// No key configured — allow (development)
			c.Next()
			return
		}

		key := c.GetHeader("X-Internal-Service-Key")
		if key != h.cfg.InternalServiceKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "UNAUTHORIZED",
				"message": "Invalid internal service key",
			})
			return
		}
		c.Next()
	}
}

// ValidateSession validates a session ID and returns session info.
func (h *InternalHandler) ValidateSession(c *gin.Context) {
	var req struct {
		SessionID string `json:"sessionId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	sess, err := h.store.GetSession(c.Request.Context(), req.SessionID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":      true,
		"userId":     sess.UserID,
		"email":      sess.Email,
		"tenantId":   sess.TenantID,
		"tenantSlug": sess.TenantSlug,
		"clientType": sess.ClientType,
		"expiresAt":  sess.ExpiresAt,
	})
}

// ExchangeToken exchanges a session for an access token (service-to-service).
func (h *InternalHandler) ExchangeToken(c *gin.Context) {
	var req struct {
		SessionID string `json:"sessionId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	sess, err := h.store.GetSession(c.Request.Context(), req.SessionID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "INVALID_SESSION"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"accessToken":  sess.AccessToken,
		"expiresAt":    sess.ExpiresAt,
		"userId":       sess.UserID,
		"tenantId":     sess.TenantID,
		"tenantSlug":   sess.TenantSlug,
	})
}

// ValidateWSTicket validates and consumes a WebSocket ticket.
func (h *InternalHandler) ValidateWSTicket(c *gin.Context) {
	var req struct {
		Ticket string `json:"ticket" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	ticket, err := h.store.ConsumeWSTicket(c.Request.Context(), req.Ticket)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":      true,
		"userId":     ticket.UserID,
		"tenantId":   ticket.TenantID,
		"tenantSlug": ticket.TenantSlug,
		"sessionId":  ticket.SessionID,
	})
}
