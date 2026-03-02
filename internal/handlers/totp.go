package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/tesserix/auth-bff/internal/clients"
	"github.com/tesserix/go-shared/logger"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/crypto"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
)

// TOTPHandler handles TOTP setup, verification, and management.
type TOTPHandler struct {
	cfg          *config.Config
	store        session.Store
	tenantClient *clients.TenantClient
	logger       *logger.Logger
}

// NewTOTPHandler creates a new TOTPHandler.
func NewTOTPHandler(cfg *config.Config, store session.Store, tc *clients.TenantClient, logger *logger.Logger) *TOTPHandler {
	return &TOTPHandler{
		cfg:          cfg,
		store:        store,
		tenantClient: tc,
		logger:       logger,
	}
}

// RegisterRoutes registers TOTP endpoints.
func (h *TOTPHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.GET("/auth/totp/status", h.Status)
	r.POST("/auth/totp/setup/initiate", h.SetupInitiate)
	r.POST("/auth/totp/setup/confirm", h.SetupConfirm)
	r.POST("/auth/totp/setup/initiate-onboarding", h.SetupInitiateOnboarding)
	r.POST("/auth/totp/setup/confirm-onboarding", h.SetupConfirmOnboarding)
	r.POST("/auth/totp/verify", h.Verify)
	r.POST("/auth/totp/disable", h.Disable)
	r.POST("/auth/totp/backup-codes/regenerate", h.RegenerateBackupCodes)
}

// Status returns TOTP status for the authenticated user.
func (h *TOTPHandler) Status(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	resp, err := h.tenantClient.GetTOTPSecret(c.Request.Context(), sess.UserID, sess.TenantID)
	if err != nil {
		h.logger.Error("get totp status", "error", err)
		c.JSON(http.StatusOK, gin.H{"success": true, "totp_enabled": false, "backup_codes_remaining": 0})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":                true,
		"totp_enabled":           resp.TOTPEnabled,
		"backup_codes_remaining": resp.BackupCodesRemaining,
	})
}

// SetupInitiate starts TOTP setup for an authenticated user.
func (h *TOTPHandler) SetupInitiate(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	h.doSetupInitiate(c, sess.UserID, sess.Email, sess.TenantSlug)
}

// SetupInitiateOnboarding starts TOTP setup during onboarding (no session required).
func (h *TOTPHandler) SetupInitiateOnboarding(c *gin.Context) {
	var req struct {
		SessionID  string `json:"session_id" binding:"required"`
		Email      string `json:"email" binding:"required"`
		TenantName string `json:"tenant_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	h.doSetupInitiate(c, "", req.Email, req.TenantName)
}

func (h *TOTPHandler) doSetupInitiate(c *gin.Context, userID, email, tenantName string) {
	issuer := "Tesserix"
	if tenantName != "" {
		issuer = fmt.Sprintf("Tesserix (%s)", tenantName)
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		h.logger.Error("generate totp key", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "TOTP_ERROR"})
		return
	}

	// Encrypt the secret
	encrypted, err := crypto.EncryptAESGCM([]byte(key.Secret()), h.cfg.EncryptionKey)
	if err != nil {
		h.logger.Error("encrypt totp secret", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "ENCRYPTION_ERROR"})
		return
	}

	// Generate backup codes
	codes, hashes, err := crypto.GenerateBackupCodes(10, h.cfg.BackupCodeHMACKey)
	if err != nil {
		h.logger.Error("generate backup codes", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "BACKUP_CODE_ERROR"})
		return
	}

	// Save setup session
	setupID := uuid.New().String()
	setupSession := &session.TOTPSetupSession{
		UserID:           userID,
		Email:            email,
		EncryptedSecret:  encrypted,
		BackupCodeHashes: hashes,
	}

	if err := h.store.SaveTOTPSetup(c.Request.Context(), setupID, setupSession); err != nil {
		h.logger.Error("save totp setup", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "SESSION_ERROR"})
		return
	}

	// Format manual entry key in groups of 4
	manualKey := formatBase32Key(key.Secret())

	c.JSON(http.StatusOK, gin.H{
		"success":          true,
		"setup_session":    setupID,
		"totp_uri":         key.URL(),
		"manual_entry_key": manualKey,
		"backup_codes":     codes,
	})
}

// SetupConfirm verifies the first TOTP code and enables TOTP.
func (h *TOTPHandler) SetupConfirm(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	var req struct {
		SetupSession string `json:"setup_session" binding:"required"`
		Code         string `json:"code" binding:"required,len=6"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	h.doSetupConfirm(c, req.SetupSession, req.Code, sess.UserID, sess.TenantID)
}

// SetupConfirmOnboarding confirms TOTP during onboarding.
func (h *TOTPHandler) SetupConfirmOnboarding(c *gin.Context) {
	var req struct {
		SetupSession string `json:"setup_session" binding:"required"`
		Code         string `json:"code" binding:"required,len=6"`
		SessionID    string `json:"session_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	// For onboarding, we don't have user/tenant IDs yet
	h.doSetupConfirm(c, req.SetupSession, req.Code, "", "")
}

func (h *TOTPHandler) doSetupConfirm(c *gin.Context, setupID, code, userID, tenantID string) {
	setupSession, err := h.store.GetTOTPSetup(c.Request.Context(), setupID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_SETUP_SESSION"})
		return
	}

	// Validate ownership
	if userID != "" && setupSession.UserID != "" && setupSession.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "FORBIDDEN"})
		return
	}

	// Decrypt secret and verify code
	secretBytes, err := crypto.DecryptAESGCM(setupSession.EncryptedSecret, h.cfg.EncryptionKey)
	if err != nil {
		h.logger.Error("decrypt totp secret", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "DECRYPTION_ERROR"})
		return
	}

	valid := totp.Validate(code, string(secretBytes))
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_TOTP_CODE", "message": "Invalid verification code"})
		return
	}

	// Persist TOTP if we have user/tenant context
	if userID != "" && tenantID != "" {
		if err := h.tenantClient.EnableTOTP(c.Request.Context(), userID, tenantID,
			setupSession.EncryptedSecret, setupSession.BackupCodeHashes); err != nil {
			h.logger.Error("enable totp", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "TOTP_ENABLE_ERROR"})
			return
		}
	}

	// Delete setup session
	_ = h.store.DeleteTOTPSetup(c.Request.Context(), setupID)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "TOTP has been enabled"})
}

// Verify verifies a TOTP code for the authenticated user.
func (h *TOTPHandler) Verify(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	valid, err := h.VerifyCode(c.Request.Context(), sess.UserID, sess.TenantID, req.Code)
	if err != nil {
		h.logger.Error("verify totp", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "TOTP_ERROR"})
		return
	}

	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "INVALID_TOTP_CODE"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "verified": true})
}

// VerifyCode verifies a TOTP or backup code. Exported for use by DirectAuthHandler.
func (h *TOTPHandler) VerifyCode(ctx context.Context, userID, tenantID, code string) (bool, error) {
	totpResp, err := h.tenantClient.GetTOTPSecret(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	if !totpResp.TOTPEnabled || totpResp.TOTPSecretEncrypted == "" {
		return false, nil
	}

	// Decrypt the secret
	secretBytes, err := crypto.DecryptAESGCM(totpResp.TOTPSecretEncrypted, h.cfg.EncryptionKey)
	if err != nil {
		return false, fmt.Errorf("decrypt totp secret: %w", err)
	}

	// Try TOTP verification first (with 1-period window)
	if totp.Validate(code, string(secretBytes)) {
		return true, nil
	}

	// Try backup code
	normalized := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	idx := crypto.VerifyBackupCode(normalized, totpResp.BackupCodeHashes, h.cfg.BackupCodeHMACKey)
	if idx >= 0 {
		// Consume the backup code
		hash := crypto.HMACCode(normalized, h.cfg.BackupCodeHMACKey)
		_ = h.tenantClient.ConsumeBackupCode(ctx, userID, tenantID, hash)
		return true, nil
	}

	return false, nil
}

// Disable disables TOTP for the authenticated user.
func (h *TOTPHandler) Disable(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required,len=6"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	// Verify current TOTP code before disabling
	valid, err := h.VerifyCode(c.Request.Context(), sess.UserID, sess.TenantID, req.Code)
	if err != nil || !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "INVALID_TOTP_CODE"})
		return
	}

	if err := h.tenantClient.DisableTOTP(c.Request.Context(), sess.UserID, sess.TenantID); err != nil {
		h.logger.Error("disable totp", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "TOTP_DISABLE_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "TOTP has been disabled"})
}

// RegenerateBackupCodes generates new backup codes.
func (h *TOTPHandler) RegenerateBackupCodes(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required,len=6"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	// Verify TOTP code
	valid, err := h.VerifyCode(c.Request.Context(), sess.UserID, sess.TenantID, req.Code)
	if err != nil || !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "INVALID_TOTP_CODE"})
		return
	}

	// Generate new codes
	codes, hashes, err := crypto.GenerateBackupCodes(10, h.cfg.BackupCodeHMACKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "BACKUP_CODE_ERROR"})
		return
	}

	if err := h.tenantClient.RegenerateBackupCodes(c.Request.Context(), sess.UserID, sess.TenantID, hashes); err != nil {
		h.logger.Error("regenerate backup codes", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "BACKUP_CODE_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"backup_codes": codes,
	})
}

func formatBase32Key(secret string) string {
	secret = strings.ToUpper(secret)
	var parts []string
	for i := 0; i < len(secret); i += 4 {
		end := i + 4
		if end > len(secret) {
			end = len(secret)
		}
		parts = append(parts, secret[i:end])
	}
	return strings.Join(parts, " ")
}

