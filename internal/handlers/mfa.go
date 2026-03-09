package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/tesserix/auth-bff/internal/clients"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/crypto"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
)

// MFAHandler consolidates TOTP and passkey operations.
type MFAHandler struct {
	cfg          *config.Config
	sessions     *session.CookieStore
	ephemeral    *session.EphemeralStore
	tenantClient *clients.TenantClient
}

// NewMFAHandler creates a new consolidated MFA handler.
func NewMFAHandler(cfg *config.Config, sessions *session.CookieStore, ephemeral *session.EphemeralStore, tc *clients.TenantClient) *MFAHandler {
	return &MFAHandler{
		cfg:          cfg,
		sessions:     sessions,
		ephemeral:    ephemeral,
		tenantClient: tc,
	}
}

// RegisterRoutes registers MFA endpoints.
func (h *MFAHandler) RegisterRoutes(r *gin.RouterGroup) {
	// TOTP
	r.POST("/auth/mfa/totp/setup", middleware.RequireSession(), h.TOTPSetup)
	r.POST("/auth/mfa/totp/verify-setup", middleware.RequireSession(), h.TOTPVerifySetup)
	r.POST("/auth/mfa/totp/verify", h.TOTPVerify)
	r.POST("/auth/mfa/totp/disable", middleware.RequireSession(), h.TOTPDisable)

	// Passkeys
	r.POST("/auth/mfa/passkey/register-begin", middleware.RequireSession(), h.PasskeyRegisterBegin)
	r.POST("/auth/mfa/passkey/register-finish", middleware.RequireSession(), h.PasskeyRegisterFinish)
	r.GET("/auth/mfa/passkeys", middleware.RequireSession(), h.ListPasskeys)
	r.DELETE("/auth/mfa/passkeys/:id", middleware.RequireSession(), h.DeletePasskey)
}

// TOTPSetup generates a new TOTP secret and backup codes for the user.
func (h *MFAHandler) TOTPSetup(c *gin.Context) {
	sess := middleware.GetSession(c)

	// Generate TOTP secret (handled by tenant-service which stores it)
	secret := generateRandom(32)
	encrypted, err := crypto.EncryptAESGCM([]byte(secret), h.cfg.EncryptionKey)
	if err != nil {
		slog.Error("mfa: encrypt totp secret", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SETUP_FAILED"})
		return
	}

	// Generate backup codes
	backupCodes := make([]string, 10)
	for i := range backupCodes {
		backupCodes[i] = generateRandom(8)
	}

	// Store setup temporarily (5 min)
	setupKey := "totp_setup:" + sess.UserID
	setupData, _ := json.Marshal(map[string]interface{}{
		"encrypted_secret": encrypted,
		"backup_codes":     backupCodes,
	})
	h.ephemeral.Set(setupKey, setupData, 5*time.Minute)

	c.JSON(http.StatusOK, gin.H{
		"secret":       secret,
		"backup_codes": backupCodes,
		"setup_id":     uuid.New().String(),
	})
}

// TOTPVerifySetup confirms setup by verifying a TOTP code, then persists.
func (h *MFAHandler) TOTPVerifySetup(c *gin.Context) {
	sess := middleware.GetSession(c)

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}

	setupKey := "totp_setup:" + sess.UserID
	data, ok := h.ephemeral.Get(setupKey)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SETUP_EXPIRED"})
		return
	}

	var setup struct {
		EncryptedSecret string   `json:"encrypted_secret"`
		BackupCodes     []string `json:"backup_codes"`
	}
	if err := json.Unmarshal(data, &setup); err != nil {
		slog.Error("mfa: unmarshal setup data", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SETUP_FAILED"})
		return
	}

	// Decrypt TOTP secret and verify the code before enabling
	secret, err := crypto.DecryptAESGCM(setup.EncryptedSecret, h.cfg.EncryptionKey)
	if err != nil {
		slog.Error("mfa: decrypt totp secret", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SETUP_FAILED"})
		return
	}
	if !crypto.ValidateTOTP(string(secret), req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_CODE"})
		return
	}

	// Hash backup codes
	backupHashes := make([]string, len(setup.BackupCodes))
	for i, code := range setup.BackupCodes {
		backupHashes[i] = crypto.HMACCode(code, h.cfg.BackupCodeHMACKey)
	}

	// Persist to tenant-service
	if err := h.tenantClient.EnableTOTP(c.Request.Context(), sess.UserID, sess.TenantID, setup.EncryptedSecret, backupHashes); err != nil {
		slog.Error("mfa: enable totp", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ENABLE_FAILED"})
		return
	}

	h.ephemeral.Delete(setupKey)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// TOTPVerify verifies a TOTP code (used during MFA challenge after login).
func (h *MFAHandler) TOTPVerify(c *gin.Context) {
	var req struct {
		Code   string `json:"code" binding:"required"`
		MFARef string `json:"mfa_ref" binding:"required"` // Reference to pending MFA session
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}

	// Load MFA pending state
	mfaData, ok := h.ephemeral.Get("mfa:" + req.MFARef)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA_SESSION_EXPIRED"})
		return
	}

	var mfaState struct {
		UserID   string `json:"user_id"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(mfaData, &mfaState); err != nil {
		slog.Error("mfa: unmarshal mfa state", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "INTERNAL_ERROR"})
		return
	}

	// Fetch TOTP secret from tenant-service
	totpResp, err := h.tenantClient.GetTOTPSecret(c.Request.Context(), mfaState.UserID, mfaState.TenantID)
	if err != nil {
		slog.Error("mfa: fetch totp secret", "error", err, "user_id", mfaState.UserID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "VERIFY_FAILED"})
		return
	}
	if !totpResp.TOTPEnabled || totpResp.TOTPSecretEncrypted == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP_NOT_ENABLED"})
		return
	}

	// Decrypt secret and verify code
	secret, err := crypto.DecryptAESGCM(totpResp.TOTPSecretEncrypted, h.cfg.EncryptionKey)
	if err != nil {
		slog.Error("mfa: decrypt totp secret", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "VERIFY_FAILED"})
		return
	}

	// Check TOTP code first, then try backup codes
	if !crypto.ValidateTOTP(string(secret), req.Code) {
		// Try backup code
		codeHash := crypto.HMACCode(req.Code, h.cfg.BackupCodeHMACKey)
		matched := false
		for _, hash := range totpResp.BackupCodeHashes {
			if hash == codeHash {
				matched = true
				break
			}
		}
		if !matched {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_CODE"})
			return
		}
		// Consume the backup code
		if err := h.tenantClient.ConsumeBackupCode(c.Request.Context(), mfaState.UserID, mfaState.TenantID, codeHash); err != nil {
			slog.Error("mfa: consume backup code", "error", err)
		}
	}

	// On success, consume MFA state and create full session
	h.ephemeral.Delete("mfa:" + req.MFARef)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "MFA verified"})
}

// TOTPDisable disables TOTP for the current user.
func (h *MFAHandler) TOTPDisable(c *gin.Context) {
	sess := middleware.GetSession(c)

	if err := h.tenantClient.DisableTOTP(c.Request.Context(), sess.UserID, sess.TenantID); err != nil {
		slog.Error("mfa: disable totp", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DISABLE_FAILED"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// PasskeyRegisterBegin starts WebAuthn registration.
func (h *MFAHandler) PasskeyRegisterBegin(c *gin.Context) {
	// TODO: Implement with go-webauthn library
	c.JSON(http.StatusNotImplemented, gin.H{"error": "NOT_IMPLEMENTED"})
}

// PasskeyRegisterFinish completes WebAuthn registration.
func (h *MFAHandler) PasskeyRegisterFinish(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "NOT_IMPLEMENTED"})
}

// ListPasskeys returns all passkeys for the current user.
func (h *MFAHandler) ListPasskeys(c *gin.Context) {
	sess := middleware.GetSession(c)

	passkeys, err := h.tenantClient.GetPasskeys(c.Request.Context(), sess.UserID, sess.TenantID)
	if err != nil {
		slog.Error("mfa: list passkeys", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "FETCH_FAILED"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"passkeys": passkeys})
}

// DeletePasskey removes a passkey.
func (h *MFAHandler) DeletePasskey(c *gin.Context) {
	sess := middleware.GetSession(c)
	credID := c.Param("id")

	if err := h.tenantClient.DeletePasskey(c.Request.Context(), sess.UserID, sess.TenantID, credID); err != nil {
		slog.Error("mfa: delete passkey", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DELETE_FAILED"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}
