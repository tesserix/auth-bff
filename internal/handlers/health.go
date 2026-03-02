package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tesserix/auth-bff/internal/session"
)

// HealthHandler handles liveness and readiness probes.
type HealthHandler struct {
	store session.Store
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(store session.Store) *HealthHandler {
	return &HealthHandler{store: store}
}

// RegisterRoutes registers health check endpoints.
func (h *HealthHandler) RegisterRoutes(r *gin.Engine) {
	r.GET("/health", h.Health)
	r.GET("/ready", h.Ready)
}

// Health is the liveness probe — always returns 200 if the process is running.
func (h *HealthHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "auth-bff",
	})
}

// Ready is the readiness probe — checks Redis connectivity.
func (h *HealthHandler) Ready(c *gin.Context) {
	if err := h.store.Ping(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "unavailable",
			"service": "auth-bff",
			"error":   "redis_unavailable",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ready",
		"service": "auth-bff",
	})
}
