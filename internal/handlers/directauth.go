package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tesserix/auth-bff/internal/clients"
	"github.com/tesserix/go-shared/logger"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/session"
)

// DirectAuthHandler handles password-based authentication flows.
type DirectAuthHandler struct {
	cfg          *config.Config
	store        session.Store
	tenantClient *clients.TenantClient
	logger       *logger.Logger
}

// NewDirectAuthHandler creates a new DirectAuthHandler.
func NewDirectAuthHandler(cfg *config.Config, store session.Store, tc *clients.TenantClient, logger *logger.Logger) *DirectAuthHandler {
	return &DirectAuthHandler{
		cfg:          cfg,
		store:        store,
		tenantClient: tc,
		logger:       logger,
	}
}

// RegisterRoutes registers direct auth endpoints.
func (h *DirectAuthHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/auth/direct/lookup-tenants", h.LookupTenants)
	r.POST("/auth/direct/login", h.Login)
	r.POST("/auth/direct/admin/login", h.AdminLogin)
	r.POST("/auth/direct/verify-mfa", h.VerifyMFA)
	r.POST("/auth/direct/register", h.Register)
	r.POST("/auth/direct/request-password-reset", h.RequestPasswordReset)
	r.POST("/auth/direct/validate-reset-token", h.ValidateResetToken)
	r.POST("/auth/direct/reset-password", h.ResetPassword)
	r.POST("/auth/direct/change-password", h.ChangePassword)
	r.POST("/auth/direct/account-status", h.AccountStatus)
	r.POST("/auth/direct/check-deactivated", h.CheckDeactivated)
	r.POST("/auth/direct/reactivate", h.ReactivateAccount)
	r.POST("/auth/direct/deactivate", h.DeactivateAccount)
}

// LookupTenants finds tenants associated with an email.
func (h *DirectAuthHandler) LookupTenants(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST", "message": "Valid email is required"})
		return
	}

	// Rate limit by IP
	allowed, _, _ := h.store.CheckRateLimit(c.Request.Context(),
		"lookup:"+clientIP(c), 10, 60*time.Second)
	if !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "error": "RATE_LIMITED", "message": "Too many requests"})
		return
	}

	resp, err := h.tenantClient.GetUserTenants(c.Request.Context(), req.Email)
	if err != nil {
		h.logger.Error("lookup tenants", "error", err)
		// Don't reveal if email exists
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    gin.H{"tenants": []interface{}{}, "count": 0, "single_tenant": false},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    resp,
	})
}

// Login handles customer/storefront password login.
func (h *DirectAuthHandler) Login(c *gin.Context) {
	var req struct {
		Email      string `json:"email" binding:"required"`
		Password   string `json:"password" binding:"required"`
		TenantSlug string `json:"tenant_slug"`
		TenantID   string `json:"tenant_id"`
		RememberMe bool   `json:"remember_me"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	app := middleware.GetApp(c)
	authContext := "customer"
	if app != nil {
		authContext = app.AuthContext
	}

	h.doLogin(c, req.Email, req.Password, req.TenantSlug, req.TenantID, req.RememberMe, authContext, false)
}

// AdminLogin handles staff/admin password login with mandatory MFA.
func (h *DirectAuthHandler) AdminLogin(c *gin.Context) {
	var req struct {
		Email      string `json:"email" binding:"required"`
		Password   string `json:"password" binding:"required"`
		TenantSlug string `json:"tenant_slug"`
		TenantID   string `json:"tenant_id"`
		RememberMe bool   `json:"remember_me"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	h.doLogin(c, req.Email, req.Password, req.TenantSlug, req.TenantID, req.RememberMe, "staff", true)
}

func (h *DirectAuthHandler) doLogin(c *gin.Context, email, password, tenantSlug, tenantID string, rememberMe bool, authContext string, requireMFA bool) {
	// Rate limit by IP + email
	rlKey := "login:" + clientIP(c) + ":" + email
	allowed, _, _ := h.store.CheckRateLimit(c.Request.Context(), rlKey, 10, 60*time.Second)
	if !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "error": "RATE_LIMITED"})
		return
	}

	credResp, err := h.tenantClient.ValidateCredentials(c.Request.Context(), &clients.ValidateCredentialsRequest{
		Email:       email,
		Password:    password,
		TenantSlug:  tenantSlug,
		TenantID:    tenantID,
		AuthContext: authContext,
		ClientIP:    clientIP(c),
		UserAgent:   c.GetHeader("User-Agent"),
	})
	if err != nil {
		h.logger.Error("validate credentials", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AUTH_ERROR", "message": "Authentication failed"})
		return
	}

	if !credResp.Valid {
		// Account locked
		if credResp.AccountLocked {
			c.JSON(http.StatusLocked, gin.H{
				"success":      false,
				"error":        "ACCOUNT_LOCKED",
				"message":      "Account is temporarily locked",
				"locked_until": credResp.LockedUntil,
			})
			return
		}
		// Google-linked account
		if credResp.GoogleLinked {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "GOOGLE_LINKED",
				"message": "This account uses Google Sign-In. Please sign in with Google.",
			})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "INVALID_CREDENTIALS",
			"message": "Invalid email or password",
		})
		return
	}

	// Check MFA requirements
	if credResp.MFARequired || (requireMFA && credResp.MFAEnabled) {
		// Check trusted device (for admin login)
		if requireMFA {
			deviceHash, _ := c.Cookie("device_trust")
			if deviceHash != "" {
				userID, err := h.store.GetDeviceTrust(c.Request.Context(), deviceHash)
				if err == nil && userID == credResp.UserID {
					// Device trusted — skip MFA
					goto createSession
				}
			}
		}

		// Create MFA session (deferred session creation)
		mfaID := uuid.New().String()
		mfaSession := &session.MFASession{
			ID:           mfaID,
			UserID:       credResp.UserID,
			Email:        credResp.Email,
			TenantID:     credResp.TenantID,
			TenantSlug:   credResp.TenantSlug,
			ClientType:   clientTypeForAuthContext(authContext),
			AccessToken:  credResp.AccessToken,
			IDToken:      credResp.IDToken,
			RefreshToken: credResp.RefreshToken,
			ExpiresAt:    time.Now().Add(time.Duration(credResp.ExpiresIn) * time.Second).Unix(),
			MFAEnabled:   credResp.MFAEnabled,
			TOTPEnabled:  credResp.TOTPEnabled,
			AttemptCount: 0,
		}

		if err := h.store.SaveMFASession(c.Request.Context(), mfaSession); err != nil {
			h.logger.Error("save mfa session", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "SESSION_ERROR"})
			return
		}

		mfaMethods := []string{}
		if credResp.TOTPEnabled {
			mfaMethods = append(mfaMethods, "totp")
		}
		if credResp.MFAEnabled {
			mfaMethods = append(mfaMethods, "email")
		}

		resp := gin.H{
			"success":      true,
			"mfa_required": true,
			"mfa_session":  mfaID,
			"mfa_methods":  mfaMethods,
			"message":      "Multi-factor authentication required.",
		}
		if requireMFA {
			resp["totp_enabled"] = credResp.TOTPEnabled
		}

		c.JSON(http.StatusOK, resp)
		return
	}

createSession:
	// Create full session
	app := middleware.GetApp(c)
	sessionID := uuid.New().String()
	csrfToken := uuid.New().String()

	sess := &session.Session{
		ID:           sessionID,
		UserID:       credResp.UserID,
		Email:        credResp.Email,
		TenantID:     credResp.TenantID,
		TenantSlug:   credResp.TenantSlug,
		ClientType:   clientTypeForAuthContext(authContext),
		AccessToken:  credResp.AccessToken,
		IDToken:      credResp.IDToken,
		RefreshToken: credResp.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(credResp.ExpiresIn) * time.Second).Unix(),
		CSRFToken:    csrfToken,
	}
	if app != nil {
		sess.AppName = app.Name
	}

	if err := h.store.CreateSession(c.Request.Context(), sess); err != nil {
		h.logger.Error("create session", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "SESSION_ERROR"})
		return
	}

	// Set session cookie
	if app != nil {
		host := middleware.GetEffectiveHost(c)
		domain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
		secure := !h.cfg.IsDevelopment()
		maxAge := int(h.cfg.SessionMaxAge.Seconds())
		if rememberMe {
			maxAge *= 7 // 7x default for remember_me
		}
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(app.SessionCookie, sessionID, maxAge, "/", domain, secure, true)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"authenticated": true,
		"user": gin.H{
			"id":          credResp.UserID,
			"email":       credResp.Email,
			"first_name":  credResp.FirstName,
			"last_name":   credResp.LastName,
			"tenant_id":   credResp.TenantID,
			"tenant_slug": credResp.TenantSlug,
			"role":        credResp.Role,
		},
		"session": gin.H{
			"expires_at": sess.ExpiresAt,
			"csrf_token": csrfToken,
		},
	})
}

// VerifyMFA completes MFA verification and creates a full session.
func (h *DirectAuthHandler) VerifyMFA(c *gin.Context) {
	var req struct {
		MFASession  string `json:"mfa_session" binding:"required"`
		Code        string `json:"code" binding:"required"`
		Method      string `json:"method"` // "totp", "email"
		TrustDevice bool   `json:"trust_device"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	mfaSess, err := h.store.GetMFASession(c.Request.Context(), req.MFASession)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_MFA_SESSION", "message": "MFA session expired or invalid"})
		return
	}

	// Check attempt count
	if mfaSess.AttemptCount >= 5 {
		_ = h.store.DeleteMFASession(c.Request.Context(), mfaSess.ID)
		c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "error": "MAX_MFA_ATTEMPTS"})
		return
	}

	// Increment attempts
	mfaSess.AttemptCount++
	_ = h.store.UpdateMFASession(c.Request.Context(), mfaSess)

	// Verify based on method
	verified := false
	switch req.Method {
	case "totp", "":
		verified, err = h.verifyTOTPCode(c, mfaSess, req.Code)
	case "email":
		verified, err = h.verifyEmailOTP(c, mfaSess, req.Code)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_MFA_METHOD"})
		return
	}

	if err != nil {
		h.logger.Error("mfa verification", "method", req.Method, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "MFA_ERROR"})
		return
	}

	if !verified {
		remaining := 5 - mfaSess.AttemptCount
		c.JSON(http.StatusUnauthorized, gin.H{
			"success":            false,
			"error":              "INVALID_MFA_CODE",
			"message":            "Invalid verification code",
			"remaining_attempts": remaining,
		})
		return
	}

	// MFA verified — create full session
	_ = h.store.DeleteMFASession(c.Request.Context(), mfaSess.ID)

	app := middleware.GetApp(c)
	sessionID := uuid.New().String()
	csrfToken := uuid.New().String()

	sess := &session.Session{
		ID:           sessionID,
		UserID:       mfaSess.UserID,
		Email:        mfaSess.Email,
		TenantID:     mfaSess.TenantID,
		TenantSlug:   mfaSess.TenantSlug,
		ClientType:   mfaSess.ClientType,
		AccessToken:  mfaSess.AccessToken,
		IDToken:      mfaSess.IDToken,
		RefreshToken: mfaSess.RefreshToken,
		ExpiresAt:    mfaSess.ExpiresAt,
		CSRFToken:    csrfToken,
	}
	if app != nil {
		sess.AppName = app.Name
	}

	if err := h.store.CreateSession(c.Request.Context(), sess); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "SESSION_ERROR"})
		return
	}

	// Set session cookie
	if app != nil {
		host := middleware.GetEffectiveHost(c)
		domain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
		secure := !h.cfg.IsDevelopment()
		maxAge := int(h.cfg.SessionMaxAge.Seconds())
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(app.SessionCookie, sessionID, maxAge, "/", domain, secure, true)
	}

	// Device trust if requested
	if req.TrustDevice {
		trustHash := uuid.New().String()
		_ = h.store.SaveDeviceTrust(c.Request.Context(), trustHash, mfaSess.UserID)
		host := middleware.GetEffectiveHost(c)
		domain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
		secure := !h.cfg.IsDevelopment()
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("device_trust", trustHash, int(session.TTLDeviceTrust.Seconds()), "/", domain, secure, true)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"authenticated": true,
		"user": gin.H{
			"id":          mfaSess.UserID,
			"email":       mfaSess.Email,
			"tenant_id":   mfaSess.TenantID,
			"tenant_slug": mfaSess.TenantSlug,
		},
		"session": gin.H{
			"expires_at": sess.ExpiresAt,
			"csrf_token": csrfToken,
		},
	})
}

// verifyTOTPCode verifies a TOTP code (or backup code) against the stored secret.
func (h *DirectAuthHandler) verifyTOTPCode(c *gin.Context, mfaSess *session.MFASession, code string) (bool, error) {
	// This will be wired to the TOTP handler's verification logic
	// For now, delegate to tenant-service which handles TOTP verification
	totpResp, err := h.tenantClient.GetTOTPSecret(c.Request.Context(), mfaSess.UserID, mfaSess.TenantID)
	if err != nil {
		return false, err
	}

	if !totpResp.TOTPEnabled || totpResp.TOTPSecretEncrypted == "" {
		return false, nil
	}

	// The actual TOTP verification is done by the TOTPHandler.VerifyCode
	// which will be injected as a dependency. For MFA flow, we re-use that logic.
	// This is a placeholder — the actual wiring happens in main.go
	return false, nil
}

// verifyEmailOTP verifies an email OTP code.
func (h *DirectAuthHandler) verifyEmailOTP(c *gin.Context, mfaSess *session.MFASession, code string) (bool, error) {
	// This will be wired to the verification client
	return false, nil
}

// Register handles new customer registration.
func (h *DirectAuthHandler) Register(c *gin.Context) {
	var req struct {
		Email      string `json:"email" binding:"required,email"`
		Password   string `json:"password" binding:"required,min=8"`
		FirstName  string `json:"first_name" binding:"required"`
		LastName   string `json:"last_name" binding:"required"`
		Phone      string `json:"phone"`
		TenantSlug string `json:"tenant_slug" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST", "message": err.Error()})
		return
	}

	resp, err := h.tenantClient.RegisterCustomer(c.Request.Context(), &clients.RegisterCustomerRequest{
		Email:      req.Email,
		Password:   req.Password,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Phone:      req.Phone,
		TenantSlug: req.TenantSlug,
	})
	if err != nil {
		h.logger.Error("register customer", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "REGISTRATION_ERROR"})
		return
	}
	if !resp.Success {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": resp.Error, "message": resp.Message})
		return
	}

	// Create session if tokens were returned
	if resp.AccessToken != "" {
		app := middleware.GetApp(c)
		sessionID := uuid.New().String()
		csrfToken := uuid.New().String()

		sess := &session.Session{
			ID:           sessionID,
			UserID:       resp.UserID,
			Email:        req.Email,
			TenantSlug:   req.TenantSlug,
			ClientType:   "customer",
			AccessToken:  resp.AccessToken,
			IDToken:      resp.IDToken,
			RefreshToken: resp.RefreshToken,
			ExpiresAt:    time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second).Unix(),
			CSRFToken:    csrfToken,
		}

		if err := h.store.CreateSession(c.Request.Context(), sess); err != nil {
			h.logger.Error("create session after register", "error", err)
		}

		if app != nil {
			host := middleware.GetEffectiveHost(c)
			domain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
			secure := !h.cfg.IsDevelopment()
			maxAge := int(h.cfg.SessionMaxAge.Seconds())
			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(app.SessionCookie, sessionID, maxAge, "/", domain, secure, true)
		}

		c.JSON(http.StatusOK, gin.H{
			"success":       true,
			"authenticated": true,
			"user": gin.H{
				"id":    resp.UserID,
				"email": req.Email,
			},
			"session": gin.H{
				"expires_at": sess.ExpiresAt,
				"csrf_token": csrfToken,
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// RequestPasswordReset initiates a password reset.
func (h *DirectAuthHandler) RequestPasswordReset(c *gin.Context) {
	var req struct {
		Email      string `json:"email" binding:"required,email"`
		TenantSlug string `json:"tenant_slug"`
		Context    string `json:"context"` // "admin" or "storefront"
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	if err := h.tenantClient.RequestPasswordReset(c.Request.Context(), &clients.PasswordResetRequest{
		Email:      req.Email,
		TenantSlug: req.TenantSlug,
		Context:    req.Context,
	}); err != nil {
		h.logger.Warn("request password reset", "error", err)
	}

	// Always return success (don't reveal email existence)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "If the email exists, a password reset link has been sent.",
	})
}

// ValidateResetToken checks if a reset token is valid.
func (h *DirectAuthHandler) ValidateResetToken(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	valid, expiresIn, err := h.tenantClient.ValidateResetToken(c.Request.Context(), req.Token)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": valid, "expires_in": expiresIn})
}

// ResetPassword completes a password reset.
func (h *DirectAuthHandler) ResetPassword(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	if err := h.tenantClient.ResetPassword(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		h.logger.Error("reset password", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "RESET_FAILED", "message": "Password reset failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Password has been reset successfully"})
}

// ChangePassword changes an authenticated user's password.
func (h *DirectAuthHandler) ChangePassword(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	if err := h.tenantClient.ChangePassword(c.Request.Context(), sess.UserID, req.CurrentPassword, req.NewPassword); err != nil {
		h.logger.Error("change password", "error", err, "user_id", sess.UserID)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "CHANGE_PASSWORD_FAILED"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Password changed successfully"})
}

// AccountStatus checks account lock status.
func (h *DirectAuthHandler) AccountStatus(c *gin.Context) {
	var req struct {
		Email      string `json:"email" binding:"required"`
		TenantSlug string `json:"tenant_slug"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	resp, err := h.tenantClient.CheckAccountStatus(c.Request.Context(), req.Email, req.TenantSlug)
	if err != nil {
		// Don't reveal account existence
		c.JSON(http.StatusOK, gin.H{"success": true, "account_locked": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":        true,
		"account_locked": resp.AccountLocked,
		"locked_until":   resp.LockedUntil,
	})
}

// CheckDeactivated checks if an account is deactivated.
func (h *DirectAuthHandler) CheckDeactivated(c *gin.Context) {
	var req struct {
		Email      string `json:"email" binding:"required"`
		TenantSlug string `json:"tenant_slug"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	resp, err := h.tenantClient.CheckDeactivated(c.Request.Context(), req.Email, req.TenantSlug)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "is_deactivated": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":          true,
		"is_deactivated":   resp.IsDeactivated,
		"can_reactivate":   resp.CanReactivate,
		"days_until_purge": resp.DaysUntilPurge,
		"purge_date":       resp.PurgeDate,
	})
}

// ReactivateAccount reactivates a deactivated account.
func (h *DirectAuthHandler) ReactivateAccount(c *gin.Context) {
	var req struct {
		Email      string `json:"email" binding:"required"`
		Password   string `json:"password" binding:"required"`
		TenantSlug string `json:"tenant_slug"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	if err := h.tenantClient.ReactivateAccount(c.Request.Context(), req.Email, req.Password, req.TenantSlug); err != nil {
		h.logger.Error("reactivate account", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "REACTIVATION_FAILED"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Account reactivated successfully"})
}

// DeactivateAccount deactivates the authenticated user's account.
func (h *DirectAuthHandler) DeactivateAccount(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&req)

	if err := h.tenantClient.DeactivateAccount(c.Request.Context(), sess.UserID, sess.TenantID, req.Reason); err != nil {
		h.logger.Error("deactivate account", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "DEACTIVATION_FAILED"})
		return
	}

	// Delete session
	_ = h.store.DeleteSession(c.Request.Context(), sess.ID)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Account deactivated"})
}

func clientTypeForAuthContext(authContext string) string {
	if authContext == "customer" {
		return "customer"
	}
	return "internal"
}

func clientIP(c *gin.Context) string {
	if ip := c.GetHeader("cf-connecting-ip"); ip != "" {
		return ip
	}
	if ip := c.GetHeader("x-real-ip"); ip != "" {
		return ip
	}
	return c.ClientIP()
}
