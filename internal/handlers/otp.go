package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tesserix/auth-bff/internal/clients"
	"github.com/tesserix/go-shared/logger"
	"github.com/tesserix/auth-bff/internal/session"
)

// OTPHandler handles email/SMS OTP verification.
type OTPHandler struct {
	store              session.Store
	verificationClient *clients.VerificationClient
	logger             *logger.Logger
}

// NewOTPHandler creates a new OTPHandler.
func NewOTPHandler(store session.Store, vc *clients.VerificationClient, logger *logger.Logger) *OTPHandler {
	return &OTPHandler{
		store:              store,
		verificationClient: vc,
		logger:             logger,
	}
}

// RegisterRoutes registers OTP endpoints.
func (h *OTPHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/auth/otp/send", h.Send)
	r.POST("/auth/otp/verify", h.Verify)
	r.POST("/auth/otp/resend", h.Resend)
	r.GET("/auth/otp/status", h.Status)
}

// Send sends a verification code.
func (h *OTPHandler) Send(c *gin.Context) {
	var req struct {
		Email    string            `json:"email" binding:"required,email"`
		Channel  string            `json:"channel"` // "email" or "sms"
		Purpose  string            `json:"purpose" binding:"required"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	if req.Channel == "" {
		req.Channel = "email"
	}

	// Rate limit: 3 send attempts per 60s per IP+email
	rlKey := "otp_send:" + clientIP(c) + ":" + req.Email
	allowed, _, _ := h.store.CheckRateLimit(c.Request.Context(), rlKey, 3, 60*time.Second)
	if !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"success": false,
			"error":   "RATE_LIMITED",
			"message": "Too many OTP requests. Please wait before trying again.",
		})
		return
	}

	resp, err := h.verificationClient.SendOTP(c.Request.Context(), &clients.SendOTPRequest{
		Recipient: req.Email,
		Channel:   req.Channel,
		Purpose:   req.Purpose,
		Metadata:  req.Metadata,
	})
	if err != nil {
		h.logger.Error("send otp", "error", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "OTP_SERVICE_UNAVAILABLE"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": resp.Success,
		"message": "Verification code sent",
		"data":    resp.Data,
	})
}

// Verify verifies a submitted OTP code.
func (h *OTPHandler) Verify(c *gin.Context) {
	var req struct {
		Email   string `json:"email" binding:"required,email"`
		Code    string `json:"code" binding:"required"`
		Purpose string `json:"purpose" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	// Rate limit: 10 verify attempts per 60s per IP+email
	rlKey := "otp_verify:" + clientIP(c) + ":" + req.Email
	allowed, _, _ := h.store.CheckRateLimit(c.Request.Context(), rlKey, 10, 60*time.Second)
	if !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"success": false,
			"error":   "RATE_LIMITED",
			"message": "Too many verification attempts",
		})
		return
	}

	resp, err := h.verificationClient.VerifyOTP(c.Request.Context(), &clients.VerifyOTPRequest{
		Recipient: req.Email,
		Code:      req.Code,
		Purpose:   req.Purpose,
	})
	if err != nil {
		h.logger.Error("verify otp", "error", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "OTP_SERVICE_UNAVAILABLE"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":           resp.Success,
		"verified":          resp.Verified,
		"message":           resp.Message,
		"remainingAttempts": resp.RemainingAttempts,
	})
}

// Resend resends a verification code.
func (h *OTPHandler) Resend(c *gin.Context) {
	// Same logic as Send
	h.Send(c)
}

// Status checks verification status.
func (h *OTPHandler) Status(c *gin.Context) {
	email := c.Query("email")
	purpose := c.Query("purpose")

	if email == "" || purpose == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	resp, err := h.verificationClient.GetOTPStatus(c.Request.Context(), email, purpose)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "OTP_SERVICE_UNAVAILABLE"})
		return
	}

	c.JSON(http.StatusOK, resp)
}
