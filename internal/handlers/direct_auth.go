package handlers

import (
	"crypto/rand"
	"encoding/hex"
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

// mfaPendingState holds validated credentials while waiting for MFA completion.
// Stored in the ephemeral store under "mfa_pending:<ref>" with a 5-minute TTL.
type mfaPendingState struct {
	UserID       string `json:"uid"`
	IDPUserID    string `json:"idp_uid"`
	Email        string `json:"email"`
	TenantID     string `json:"tid"`
	TenantSlug   string `json:"ts"`
	Role         string `json:"role"`
	FirstName    string `json:"fn"`
	LastName     string `json:"ln"`
	AccessToken  string `json:"at"`
	IDToken      string `json:"idt"`
	RefreshToken string `json:"rt"`
	ExpiresIn    int    `json:"exp_in"`
	TOTPEnabled  bool   `json:"totp"`
	AppName      string `json:"app"`
}

// DirectAuthHandler handles direct email/password login for admin and storefront.
type DirectAuthHandler struct {
	cfg                *config.Config
	sessions           *session.CookieStore
	ephemeral          *session.EphemeralStore
	events             *events.Publisher
	tenantClient       *clients.TenantClient
	verificationClient *clients.VerificationClient
}

// NewDirectAuthHandler creates a new DirectAuthHandler.
func NewDirectAuthHandler(
	cfg *config.Config,
	sessions *session.CookieStore,
	ephemeral *session.EphemeralStore,
	events *events.Publisher,
	tc *clients.TenantClient,
	vc *clients.VerificationClient,
) *DirectAuthHandler {
	return &DirectAuthHandler{
		cfg:                cfg,
		sessions:           sessions,
		ephemeral:          ephemeral,
		events:             events,
		tenantClient:       tc,
		verificationClient: vc,
	}
}

// RegisterRoutes registers direct authentication endpoints.
func (h *DirectAuthHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/auth/direct/admin/login", h.AdminLogin)
	r.POST("/auth/direct/mfa/verify", h.MFAVerify)
	r.POST("/auth/direct/mfa/send-code", h.MFASendCode)
}

// AdminLogin authenticates admin/staff users via tenant-service credential validation.
// Tenant-service verifies: password via GIP, tenant membership, account lock status, and MFA.
func (h *DirectAuthHandler) AdminLogin(c *gin.Context) {
	var req struct {
		Email      string `json:"email" binding:"required"`
		Password   string `json:"password" binding:"required"`
		TenantSlug string `json:"tenant_slug" binding:"required"`
		RememberMe bool   `json:"remember_me"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Missing required fields"})
		return
	}

	// Resolve admin app config for session cookie settings
	app := middleware.GetAppByName(c, "admin")
	if app == nil {
		app = middleware.GetApp(c)
	}
	if app == nil {
		slog.Warn("direct-login: could not resolve admin app config")
		c.JSON(http.StatusBadRequest, gin.H{"error": "UNKNOWN_APP"})
		return
	}

	// Validate credentials via tenant-service, which checks:
	// 1. User exists and belongs to the requested tenant (membership)
	// 2. Password is correct (via GIP)
	// 3. Account is not locked
	// 4. MFA requirements
	result, err := h.tenantClient.ValidateCredentials(c.Request.Context(), &clients.ValidateCredentialsRequest{
		Email:       req.Email,
		Password:    req.Password,
		TenantSlug:  req.TenantSlug,
		AuthContext: "staff",
		ClientIP:    c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
	})
	if err != nil {
		slog.Error("direct-login: tenant-service validate-credentials failed", "error", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "SERVICE_UNAVAILABLE",
			"message": "Authentication service is temporarily unavailable.",
		})
		return
	}

	// Account locked
	if result.AccountLocked {
		c.JSON(http.StatusLocked, gin.H{
			"success":      false,
			"error":        "ACCOUNT_LOCKED",
			"message":      "Your account has been locked due to too many failed attempts.",
			"locked_until": result.LockedUntil,
		})
		return
	}

	// Invalid credentials or not a member of this tenant
	if !result.Valid {
		h.events.PublishLoginFailed(c.Request.Context(), result.TenantID, req.Email, c.ClientIP(), c.GetHeader("User-Agent"), "invalid_credentials")
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   result.Error,
			"message": "Invalid email or password.",
		})
		return
	}

	// MFA required — store validated credentials in ephemeral state, return mfa_session ref
	if result.MFARequired {
		mfaRef, err := h.storeMFAPending(result, app.Name)
		if err != nil {
			slog.Error("direct-login: store mfa pending state", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "INTERNAL_ERROR",
				"message": "Failed to initiate MFA challenge.",
			})
			return
		}

		slog.Info("direct-login: MFA required", "user_id", result.IDPUserID, "tenant_slug", result.TenantSlug)
		c.JSON(http.StatusOK, gin.H{
			"success":      true,
			"mfa_required": true,
			"mfa_session":  mfaRef,
			"mfa_methods":  mfaMethods(result),
		})
		return
	}

	// Credentials valid, no MFA — create session directly
	h.createSessionAndRespond(c, result, app)
}

// MFAVerify verifies the MFA code and completes the login by creating a session.
func (h *DirectAuthHandler) MFAVerify(c *gin.Context) {
	var req struct {
		MFASession  string `json:"mfa_session" binding:"required"`
		Code        string `json:"code" binding:"required"`
		Method      string `json:"method"`
		TrustDevice bool   `json:"trust_device"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST", "message": "Missing required fields"})
		return
	}
	if req.Method == "" {
		req.Method = "totp"
	}

	// Load (but don't consume yet) the pending MFA state
	pending, ok := h.loadMFAPending(req.MFASession)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "INVALID_MFA_SESSION",
			"message": "MFA session expired or invalid. Please sign in again.",
		})
		return
	}

	// Resolve app config
	app := middleware.GetAppByName(c, pending.AppName)
	if app == nil {
		app = middleware.GetAppByName(c, "admin")
	}
	if app == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "UNKNOWN_APP"})
		return
	}

	// Verify the code based on method
	switch req.Method {
	case "totp":
		verified, err := h.verifyTOTPCode(c, pending, req.Code)
		if err != nil {
			slog.Error("mfa-verify: totp verification error", "error", err, "user_id", pending.IDPUserID)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "VERIFICATION_ERROR",
				"message": "Failed to verify code. Please try again.",
			})
			return
		}
		if !verified {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "INVALID_CODE",
				"message": "Invalid verification code.",
			})
			return
		}

	case "email":
		verified, err := h.verifyEmailCode(c, pending, req.Code)
		if err != nil {
			slog.Error("mfa-verify: email otp verification error", "error", err, "user_id", pending.IDPUserID)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "VERIFICATION_ERROR",
				"message": "Failed to verify code. Please try again.",
			})
			return
		}
		if !verified {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "INVALID_CODE",
				"message": "Invalid verification code.",
			})
			return
		}

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "UNSUPPORTED_METHOD",
			"message": "Unsupported MFA method.",
		})
		return
	}

	// MFA verified — consume the pending state (single-use)
	h.ephemeral.Delete("mfa_pending:" + req.MFASession)

	// Build a ValidateCredentialsResponse from the pending state to reuse createSessionAndRespond
	result := &clients.ValidateCredentialsResponse{
		Valid:        true,
		UserID:       pending.UserID,
		IDPUserID:    pending.IDPUserID,
		Email:        pending.Email,
		TenantID:     pending.TenantID,
		TenantSlug:   pending.TenantSlug,
		Role:         pending.Role,
		FirstName:    pending.FirstName,
		LastName:     pending.LastName,
		AccessToken:  pending.AccessToken,
		IDToken:      pending.IDToken,
		RefreshToken: pending.RefreshToken,
		ExpiresIn:    pending.ExpiresIn,
	}

	h.createSessionAndRespond(c, result, app)
}

// MFASendCode sends an email OTP for the pending MFA session.
func (h *DirectAuthHandler) MFASendCode(c *gin.Context) {
	var req struct {
		MFASession string `json:"mfa_session" binding:"required"`
		Method     string `json:"method"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "INVALID_REQUEST"})
		return
	}
	if req.Method == "" {
		req.Method = "email"
	}

	pending, ok := h.loadMFAPending(req.MFASession)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "INVALID_MFA_SESSION",
			"message": "MFA session expired or invalid. Please sign in again.",
		})
		return
	}

	if req.Method != "email" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "UNSUPPORTED_METHOD",
			"message": "Only email OTP sending is supported.",
		})
		return
	}

	if h.verificationClient == nil {
		slog.Error("mfa-send-code: verification client not configured")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "SERVICE_UNAVAILABLE",
			"message": "Email verification is temporarily unavailable.",
		})
		return
	}

	otpResp, err := h.verificationClient.SendOTP(c.Request.Context(), &clients.SendOTPRequest{
		Recipient: pending.Email,
		Channel:   "email",
		Purpose:   "mfa_login",
		Metadata: map[string]string{
			"tenant_id": pending.TenantID,
			"user_id":   pending.IDPUserID,
		},
	})
	if err != nil || !otpResp.Success {
		slog.Error("mfa-send-code: send otp failed", "error", err, "email", pending.Email)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to send verification code.",
		})
		return
	}

	slog.Info("mfa-send-code: email otp sent", "email", pending.Email)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Verification code sent."})
}

// storeMFAPending generates a random MFA reference and stores the pending state.
func (h *DirectAuthHandler) storeMFAPending(result *clients.ValidateCredentialsResponse, appName string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	ref := hex.EncodeToString(b)

	state := mfaPendingState{
		UserID:       result.UserID,
		IDPUserID:    result.IDPUserID,
		Email:        result.Email,
		TenantID:     result.TenantID,
		TenantSlug:   result.TenantSlug,
		Role:         result.Role,
		FirstName:    result.FirstName,
		LastName:     result.LastName,
		AccessToken:  result.AccessToken,
		IDToken:      result.IDToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		TOTPEnabled:  result.TOTPEnabled,
		AppName:      appName,
	}

	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}

	h.ephemeral.Set("mfa_pending:"+ref, data, 5*time.Minute)
	return ref, nil
}

// loadMFAPending loads (non-destructively) a pending MFA state.
func (h *DirectAuthHandler) loadMFAPending(ref string) (*mfaPendingState, bool) {
	data, ok := h.ephemeral.Get("mfa_pending:" + ref)
	if !ok {
		return nil, false
	}
	var state mfaPendingState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, false
	}
	return &state, true
}

// verifyTOTPCode fetches the user's TOTP secret from tenant-service,
// decrypts it, and validates the code. Also checks backup codes.
func (h *DirectAuthHandler) verifyTOTPCode(c *gin.Context, pending *mfaPendingState, code string) (bool, error) {
	totpResp, err := h.tenantClient.GetTOTPSecret(c.Request.Context(), pending.IDPUserID, pending.TenantID)
	if err != nil {
		return false, err
	}
	if !totpResp.TOTPEnabled || totpResp.TOTPSecretEncrypted == "" {
		return false, nil
	}

	// Decrypt TOTP secret
	secret, err := crypto.DecryptAESGCM(totpResp.TOTPSecretEncrypted, h.cfg.EncryptionKey)
	if err != nil {
		return false, err
	}

	// Validate TOTP code (time-based, +-1 window)
	if crypto.ValidateTOTP(string(secret), code) {
		return true, nil
	}

	// Try backup codes
	if len(totpResp.BackupCodeHashes) > 0 {
		idx := crypto.VerifyBackupCode(code, totpResp.BackupCodeHashes, h.cfg.BackupCodeHMACKey)
		if idx >= 0 {
			// Consume the backup code
			_ = h.tenantClient.ConsumeBackupCode(c.Request.Context(), pending.IDPUserID, pending.TenantID, totpResp.BackupCodeHashes[idx])
			return true, nil
		}
	}

	return false, nil
}

// verifyEmailCode verifies an email OTP via the verification service.
func (h *DirectAuthHandler) verifyEmailCode(c *gin.Context, pending *mfaPendingState, code string) (bool, error) {
	if h.verificationClient == nil {
		return false, nil
	}

	resp, err := h.verificationClient.VerifyOTP(c.Request.Context(), &clients.VerifyOTPRequest{
		Recipient: pending.Email,
		Code:      code,
		Purpose:   "mfa_login",
	})
	if err != nil {
		return false, err
	}

	return resp.Verified, nil
}

// createSessionAndRespond creates a session cookie and returns the success response.
func (h *DirectAuthHandler) createSessionAndRespond(c *gin.Context, result *clients.ValidateCredentialsResponse, app *config.AppConfig) {
	csrfToken := uuid.New().String()
	sess := &session.Session{
		UserID:       result.IDPUserID,
		Email:        result.Email,
		TenantID:     result.TenantID,
		TenantSlug:   result.TenantSlug,
		AuthContext:  app.AuthContext,
		AccessToken:  result.AccessToken,
		IDToken:      result.IDToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).Unix(),
		CSRFToken:    csrfToken,
		AppName:      app.Name,
	}

	host := middleware.GetEffectiveHost(c)
	cookieDomain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
	if err := h.sessions.Save(c, app.SessionCookie, cookieDomain, sess); err != nil {
		slog.Error("direct-login: save session", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "SESSION_CREATE_FAILED",
			"message": "Failed to create session.",
		})
		return
	}

	h.events.PublishLoginSuccess(c.Request.Context(), result.TenantID, result.IDPUserID, result.Email, c.ClientIP(), c.GetHeader("User-Agent"), "direct")

	slog.Info("direct-login: success", "user_id", result.IDPUserID, "tenant_slug", result.TenantSlug)
	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"authenticated": true,
		"user": gin.H{
			"id":          result.IDPUserID,
			"email":       result.Email,
			"first_name":  result.FirstName,
			"last_name":   result.LastName,
			"tenant_id":   result.TenantID,
			"tenant_slug": result.TenantSlug,
			"role":        result.Role,
		},
		"session": gin.H{
			"expires_at": sess.ExpiresAt,
			"csrf_token": csrfToken,
		},
	})
}

func mfaMethods(r *clients.ValidateCredentialsResponse) []string {
	var methods []string
	if r.TOTPEnabled {
		methods = append(methods, "totp")
	}
	methods = append(methods, "email")
	return methods
}
