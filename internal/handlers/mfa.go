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
	"github.com/tesserix/auth-bff/internal/events"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
)

const mfaMaxAttempts = 5

// MFAHandler consolidates TOTP and passkey operations.
type MFAHandler struct {
	cfg          *config.Config
	sessions     *session.CookieStore
	ephemeral    *session.EphemeralStore
	tenantClient *clients.TenantClient
	events       *events.Publisher
}

// NewMFAHandler creates a new consolidated MFA handler.
func NewMFAHandler(cfg *config.Config, sessions *session.CookieStore, ephemeral *session.EphemeralStore, tc *clients.TenantClient, ep *events.Publisher) *MFAHandler {
	return &MFAHandler{
		cfg:          cfg,
		sessions:     sessions,
		ephemeral:    ephemeral,
		tenantClient: tc,
		events:       ep,
	}
}

// RegisterRoutes registers MFA endpoints.
func (h *MFAHandler) RegisterRoutes(r *gin.RouterGroup) {
	// TOTP
	r.POST("/auth/mfa/totp/setup", middleware.RequireSession(), h.TOTPSetup)
	r.POST("/auth/mfa/totp/verify-setup", middleware.RequireSession(), h.TOTPVerifySetup)
	r.POST("/auth/mfa/totp/verify", h.TOTPVerify)
	r.POST("/auth/mfa/totp/disable", middleware.RequireSession(), h.TOTPDisable)
	r.GET("/auth/mfa/totp/status", middleware.RequireSession(), h.TOTPStatus)
	r.POST("/auth/mfa/totp/regenerate-backups", middleware.RequireSession(), h.RegenerateBackupCodes)

	// Passkeys
	r.POST("/auth/mfa/passkey/register-begin", middleware.RequireSession(), h.PasskeyRegisterBegin)
	r.POST("/auth/mfa/passkey/register-finish", middleware.RequireSession(), h.PasskeyRegisterFinish)
	r.GET("/auth/mfa/passkeys", middleware.RequireSession(), h.ListPasskeys)
	r.DELETE("/auth/mfa/passkeys/:id", middleware.RequireSession(), h.DeletePasskey)
}

// TOTPSetup generates a new TOTP secret and backup codes for the user.
func (h *MFAHandler) TOTPSetup(c *gin.Context) {
	sess := middleware.GetSession(c)

	// Generate base32-encoded TOTP secret (20 random bytes)
	secret := crypto.GenerateTOTPSecret(20)
	encrypted, err := crypto.EncryptAESGCM([]byte(secret), h.cfg.EncryptionKey)
	if err != nil {
		slog.Error("mfa: encrypt totp secret", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SETUP_FAILED"})
		return
	}

	// Build otpauth:// URI for QR code generation
	totpURI := crypto.BuildTOTPURI(secret, sess.Email, "Tesserix")

	// Generate backup codes using the proper formatter (XXXX-XXXX format, unambiguous charset)
	backupCodes, backupHashes, err := crypto.GenerateBackupCodes(10, h.cfg.BackupCodeHMACKey)
	if err != nil {
		slog.Error("mfa: generate backup codes", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SETUP_FAILED"})
		return
	}

	// Store setup temporarily (5 min) with UUID-based key
	setupID := uuid.New().String()
	setupKey := "totp_setup:" + setupID
	setupData, _ := json.Marshal(map[string]interface{}{
		"encrypted_secret": encrypted,
		"backup_codes":     backupCodes,
		"backup_hashes":    backupHashes,
	})
	h.ephemeral.Set(setupKey, setupData, 5*time.Minute)

	c.JSON(http.StatusOK, gin.H{
		"success":          true,
		"setup_session":    setupID,
		"totp_uri":         totpURI,
		"manual_entry_key": secret,
		"backup_codes":     backupCodes,
	})
}

// TOTPVerifySetup confirms setup by verifying a TOTP code, then persists.
func (h *MFAHandler) TOTPVerifySetup(c *gin.Context) {
	sess := middleware.GetSession(c)

	var req struct {
		Code         string `json:"code" binding:"required"`
		SetupSession string `json:"setup_session"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}

	setupKey := "totp_setup:" + sess.UserID
	if req.SetupSession != "" {
		setupKey = "totp_setup:" + req.SetupSession
	}
	data, ok := h.ephemeral.Get(setupKey)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SETUP_EXPIRED"})
		return
	}

	var setup struct {
		EncryptedSecret string   `json:"encrypted_secret"`
		BackupCodes     []string `json:"backup_codes"`
		BackupHashes    []string `json:"backup_hashes"`
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

	// Use the pre-computed HMAC hashes from setup (already normalised by GenerateBackupCodes)
	backupHashes := setup.BackupHashes

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
// Reads the pending MFA state created by direct-auth login, enforces brute-force
// protection (max 5 attempts), and creates a full session on success.
func (h *MFAHandler) TOTPVerify(c *gin.Context) {
	var req struct {
		Code   string `json:"code" binding:"required"`
		MFARef string `json:"mfa_ref" binding:"required"` // Reference to pending MFA session
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}

	attemptsKey := "mfa_attempts:" + req.MFARef

	// Brute-force protection: check attempt counter before doing any work
	if attemptsRaw, ok := h.ephemeral.Get(attemptsKey); ok && len(attemptsRaw) > 0 {
		if int(attemptsRaw[0]) >= mfaMaxAttempts {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "MFA_SESSION_LOCKED",
				"message": "Too many failed attempts. Please sign in again.",
			})
			return
		}
	}

	// Load MFA pending state (non-destructively — still needed if code is wrong)
	mfaData, ok := h.ephemeral.Get("mfa_pending:" + req.MFARef)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA_SESSION_EXPIRED"})
		return
	}

	var pending mfaPendingState
	if err := json.Unmarshal(mfaData, &pending); err != nil {
		slog.Error("mfa: unmarshal mfa pending state", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "INTERNAL_ERROR"})
		return
	}

	// Fetch TOTP secret from tenant-service
	totpResp, err := h.tenantClient.GetTOTPSecret(c.Request.Context(), pending.IDPUserID, pending.TenantID)
	if err != nil {
		slog.Error("mfa: fetch totp secret", "error", err, "user_id", pending.IDPUserID)
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
	codeVerified := crypto.ValidateTOTP(string(secret), req.Code)
	if !codeVerified {
		// Try backup code via constant-time HMAC comparison
		idx := crypto.VerifyBackupCode(req.Code, totpResp.BackupCodeHashes, h.cfg.BackupCodeHMACKey)
		if idx >= 0 {
			codeVerified = true
			if err := h.tenantClient.ConsumeBackupCode(c.Request.Context(), pending.IDPUserID, pending.TenantID, totpResp.BackupCodeHashes[idx]); err != nil {
				slog.Error("mfa: consume backup code", "error", err)
			}
		}
	}

	if !codeVerified {
		// Increment attempt counter (TTL matches pending state lifetime)
		var count byte
		if raw, ok := h.ephemeral.Get(attemptsKey); ok && len(raw) > 0 {
			count = raw[0]
		}
		count++
		h.ephemeral.Set(attemptsKey, []byte{count}, 5*time.Minute)

		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_CODE"})
		return
	}

	// Code is valid — consume MFA state (single-use) and clear attempt counter
	h.ephemeral.Delete("mfa_pending:" + req.MFARef)
	h.ephemeral.Delete(attemptsKey)

	// Resolve app config to set the right session cookie
	app := middleware.GetAppByName(c, pending.AppName)
	if app == nil {
		app = middleware.GetAppByName(c, "admin")
	}
	if app == nil {
		slog.Error("mfa: could not resolve app config", "app_name", pending.AppName)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "INTERNAL_ERROR"})
		return
	}

	// Create full session
	csrfToken := uuid.New().String()
	sess := &session.Session{
		UserID:       pending.IDPUserID,
		Email:        pending.Email,
		TenantID:     pending.TenantID,
		TenantSlug:   pending.TenantSlug,
		AuthContext:  app.AuthContext,
		AccessToken:  pending.AccessToken,
		IDToken:      pending.IDToken,
		RefreshToken: pending.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(pending.ExpiresIn) * time.Second).Unix(),
		CSRFToken:    csrfToken,
		AppName:      app.Name,
	}

	host := middleware.GetEffectiveHost(c)
	cookieDomain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
	if err := h.sessions.Save(c, app.SessionCookie, cookieDomain, sess); err != nil {
		slog.Error("mfa: save session after totp verify", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SESSION_CREATE_FAILED"})
		return
	}

	h.events.PublishLoginSuccess(c.Request.Context(), pending.TenantID, pending.IDPUserID, pending.Email, c.ClientIP(), c.GetHeader("User-Agent"), "totp-mfa")

	slog.Info("mfa: totp verify success", "user_id", pending.IDPUserID, "tenant_slug", pending.TenantSlug)
	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"authenticated": true,
		"session": gin.H{
			"expires_at": sess.ExpiresAt,
			"csrf_token": csrfToken,
		},
	})
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

// TOTPStatus returns the current TOTP status for the logged-in user.
func (h *MFAHandler) TOTPStatus(c *gin.Context) {
	sess := middleware.GetSession(c)

	totpResp, err := h.tenantClient.GetTOTPSecret(c.Request.Context(), sess.UserID, sess.TenantID)
	if err != nil {
		// If tenant-service returns error, assume TOTP not configured
		slog.Warn("mfa: fetch totp status", "error", err, "user_id", sess.UserID)
		c.JSON(http.StatusOK, gin.H{
			"success":                true,
			"totp_enabled":           false,
			"backup_codes_remaining": 0,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":                true,
		"totp_enabled":           totpResp.TOTPEnabled,
		"backup_codes_remaining": totpResp.BackupCodesRemaining,
	})
}

// RegenerateBackupCodes generates new backup codes for the user (requires TOTP to be enabled).
func (h *MFAHandler) RegenerateBackupCodes(c *gin.Context) {
	sess := middleware.GetSession(c)

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}

	// Verify TOTP code first
	totpResp, err := h.tenantClient.GetTOTPSecret(c.Request.Context(), sess.UserID, sess.TenantID)
	if err != nil || !totpResp.TOTPEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP_NOT_ENABLED"})
		return
	}

	secret, err := crypto.DecryptAESGCM(totpResp.TOTPSecretEncrypted, h.cfg.EncryptionKey)
	if err != nil {
		slog.Error("mfa: decrypt totp secret for backup regeneration", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "VERIFY_FAILED"})
		return
	}

	if !crypto.ValidateTOTP(string(secret), req.Code) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "INVALID_CODE"})
		return
	}

	// Generate new backup codes
	backupCodes, backupHashes, err := crypto.GenerateBackupCodes(10, h.cfg.BackupCodeHMACKey)
	if err != nil {
		slog.Error("mfa: generate backup codes", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "REGENERATE_FAILED"})
		return
	}

	// Persist to tenant-service
	if err := h.tenantClient.RegenerateBackupCodes(c.Request.Context(), sess.UserID, sess.TenantID, backupHashes); err != nil {
		slog.Error("mfa: regenerate backup codes", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "REGENERATE_FAILED"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"backup_codes": backupCodes,
	})
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
