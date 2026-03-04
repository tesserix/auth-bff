package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/oidc"
	"github.com/tesserix/auth-bff/internal/session"
	"github.com/tesserix/go-shared/logger"
)

// AuthHandler handles OIDC authentication flows.
type AuthHandler struct {
	cfg         *config.Config
	store       session.Store
	oidcManager *oidc.Manager
	logger      *logger.Logger
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(cfg *config.Config, store session.Store, oidcMgr *oidc.Manager, logger *logger.Logger) *AuthHandler {
	return &AuthHandler{
		cfg:         cfg,
		store:       store,
		oidcManager: oidcMgr,
		logger:      logger,
	}
}

// RegisterRoutes registers OIDC auth endpoints.
func (h *AuthHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.GET("/auth/login", h.Login)
	r.GET("/auth/callback", h.Callback)
	r.POST("/auth/logout", h.Logout)
	r.GET("/auth/logout", h.LogoutRedirect)
	r.GET("/auth/session", h.Session)
	r.POST("/auth/refresh", h.Refresh)
	r.GET("/auth/csrf-token", h.CSRFToken)
	r.POST("/auth/ws-ticket", h.CreateWSTicket)
	r.POST("/auth/session/transfer", h.SessionTransfer)
	r.POST("/auth/token-exchange", h.requireInternalServiceKey(), h.TokenExchange)
}

// Login initiates the OIDC authorization flow with PKCE.
func (h *AuthHandler) Login(c *gin.Context) {
	app := middleware.GetApp(c)
	if app == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "UNKNOWN_APP", "message": "Could not determine application"})
		return
	}

	provider, err := h.oidcManager.GetProviderForApp(app)
	if err != nil {
		h.logger.Error("oidc provider not found", "app", app.Name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "OIDC_ERROR"})
		return
	}

	state, _ := oidc.GenerateState()
	nonce, _ := oidc.GenerateNonce()
	codeVerifier, _ := oidc.GenerateCodeVerifier()

	returnTo := sanitizeReturnTo(c.Query("returnTo"), app)
	prompt := c.Query("prompt")
	loginHint := c.Query("loginHint")
	if loginHint == "" {
		loginHint = c.Query("login_hint")
	}
	idpHint := c.Query("kc_idp_hint")
	kcAction := c.Query("kc_action")
	tenantID := c.Query("tenant_id")
	tenantSlug := c.Query("tenant_slug")

	// Extract tenant slug from hostname if not provided
	if tenantSlug == "" {
		tenantSlug = extractTenantSlug(middleware.GetEffectiveHost(c), app)
	}

	// prompt=create → kc_action=register
	if prompt == "create" {
		kcAction = "register"
		prompt = ""
	}

	// Build callback URL
	host := middleware.GetEffectiveHost(c)
	proto := c.GetHeader("x-forwarded-proto")
	if proto == "" {
		proto = "https"
	}
	callbackURL := fmt.Sprintf("%s://%s%s", proto, host, app.CallbackPath)

	// Save auth flow state (single-use)
	flowState := &session.AuthFlowState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		RedirectURI:  callbackURL,
		ClientType:   clientTypeForRealm(app.Realm),
		ReturnTo:     returnTo,
		TenantID:     tenantID,
		TenantSlug:   tenantSlug,
		IDPHint:      idpHint,
		AppName:      app.Name,
	}
	if err := h.store.SaveAuthFlowState(c.Request.Context(), flowState); err != nil {
		h.logger.Error("save auth flow state", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "SESSION_ERROR"})
		return
	}

	// Build extra params
	extraParams := map[string]string{
		"prompt":       prompt,
		"login_hint":   loginHint,
		"kc_idp_hint":  idpHint,
		"kc_action":    kcAction,
		"redirect_uri": callbackURL,
	}

	// Add first/last name for registration
	if fn := c.Query("first_name"); fn != "" {
		extraParams["first_name"] = fn
	}
	if ln := c.Query("last_name"); ln != "" {
		extraParams["last_name"] = ln
	}

	authURL := provider.AuthURL(state, nonce, codeVerifier, extraParams)
	c.Redirect(http.StatusFound, authURL)
}

// Callback handles the OIDC authorization callback.
func (h *AuthHandler) Callback(c *gin.Context) {
	code := c.Query("code")
	stateParam := c.Query("state")

	if code == "" || stateParam == "" {
		errParam := c.Query("error")
		errDesc := c.Query("error_description")
		h.logger.Warn("oidc callback error", "error", errParam, "description", errDesc)
		c.Redirect(http.StatusFound, "/login?error="+url.QueryEscape(errParam))
		return
	}

	// Retrieve and consume auth flow state (single-use)
	flowState, err := h.store.GetAuthFlowState(c.Request.Context(), stateParam)
	if err != nil {
		h.logger.Error("get auth flow state", "error", err)
		c.Redirect(http.StatusFound, "/login?error=invalid_state")
		return
	}

	// Find the app config for this flow
	app := h.resolveAppFromFlow(flowState)
	if app == nil {
		c.Redirect(http.StatusFound, "/login?error=unknown_app")
		return
	}

	provider, err := h.oidcManager.GetProviderForApp(app)
	if err != nil {
		h.logger.Error("oidc provider for callback", "error", err)
		c.Redirect(http.StatusFound, "/login?error=oidc_error")
		return
	}

	// Exchange code for tokens with PKCE
	tokens, err := provider.Exchange(c.Request.Context(), code, flowState.CodeVerifier, flowState.RedirectURI)
	if err != nil {
		h.logger.Error("oidc code exchange", "error", err)
		c.Redirect(http.StatusFound, "/login?error=exchange_failed")
		return
	}

	// Fetch user info
	userInfo, err := provider.UserInfo(c.Request.Context(), tokens.AccessToken)
	if err != nil {
		h.logger.Warn("userinfo fetch failed", "error", err)
		// Continue without full userinfo — we have ID token claims
	}

	// Build session
	sessionID := uuid.New().String()
	csrfToken := uuid.New().String()

	sess := &session.Session{
		ID:           sessionID,
		UserID:       getStringClaim(userInfo, "sub"),
		Email:        getStringClaim(userInfo, "email"),
		TenantID:     flowState.TenantID,
		TenantSlug:   flowState.TenantSlug,
		ClientType:   flowState.ClientType,
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt.Unix(),
		CSRFToken:    csrfToken,
		AppName:      app.Name,
		UserInfo:     buildUserInfo(userInfo),
	}

	// Override tenant from userinfo claims if not in flow state
	if sess.TenantID == "" {
		sess.TenantID = getStringClaim(userInfo, "tenant_id")
	}
	if sess.TenantSlug == "" {
		sess.TenantSlug = getStringClaim(userInfo, "tenant_slug")
	}

	if err := h.store.CreateSession(c.Request.Context(), sess); err != nil {
		h.logger.Error("create session", "error", err)
		c.Redirect(http.StatusFound, "/login?error=session_error")
		return
	}

	// Set session cookie
	host := middleware.GetEffectiveHost(c)
	domain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
	secure := !h.cfg.IsDevelopment()
	maxAge := int(h.cfg.SessionMaxAge.Seconds())

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(app.SessionCookie, sessionID, maxAge, "/", domain, secure, true)

	// Redirect to returnTo or default
	redirectTo := flowState.ReturnTo
	if redirectTo == "" {
		redirectTo = app.PostLoginURL
	}

	h.logger.Info("oidc login success",
		"user_id", sess.UserID,
		"app", app.Name,
		"tenant", sess.TenantSlug,
	)

	c.Redirect(http.StatusFound, redirectTo)
}

// Logout destroys the session and clears cookies.
func (h *AuthHandler) Logout(c *gin.Context) {
	app := middleware.GetApp(c)
	sess := middleware.GetSession(c)

	if sess != nil {
		// Delete session from store
		if err := h.store.DeleteSession(c.Request.Context(), sess.ID); err != nil {
			h.logger.Error("delete session", "error", err)
		}

		// Revoke refresh token (best-effort)
		if app != nil && sess.RefreshToken != "" {
			if provider, err := h.oidcManager.GetProviderForApp(app); err == nil {
				go func() {
					_ = provider.RevokeToken(c.Request.Context(), sess.RefreshToken, "refresh_token")
				}()
			}
		}
	}

	// Clear session cookie
	if app != nil {
		host := middleware.GetEffectiveHost(c)
		domain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(app.SessionCookie, "", -1, "/", domain, !h.cfg.IsDevelopment(), true)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"logged_out": true,
	})
}

// LogoutRedirect handles GET logout with redirect.
func (h *AuthHandler) LogoutRedirect(c *gin.Context) {
	app := middleware.GetApp(c)
	sess := middleware.GetSession(c)

	if sess != nil {
		_ = h.store.DeleteSession(c.Request.Context(), sess.ID)
	}

	if app != nil {
		host := middleware.GetEffectiveHost(c)
		domain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(app.SessionCookie, "", -1, "/", domain, !h.cfg.IsDevelopment(), true)
	}

	returnTo := c.Query("returnTo")
	if returnTo == "" && app != nil {
		returnTo = app.PostLogoutURL
	}
	if returnTo == "" {
		returnTo = "/login"
	}

	c.Redirect(http.StatusFound, returnTo)
}

// Session returns the authenticated user's session data (not tokens).
func (h *AuthHandler) Session(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusOK, gin.H{"authenticated": false})
		return
	}

	// Check if tokens are expired
	if time.Now().Unix() > sess.ExpiresAt {
		c.JSON(http.StatusOK, gin.H{"authenticated": false, "reason": "expired"})
		return
	}

	user := gin.H{
		"id":    sess.UserID,
		"email": sess.Email,
	}
	if sess.UserInfo != nil {
		user["name"] = sess.UserInfo.Name
		user["firstName"] = sess.UserInfo.GivenName
		user["lastName"] = sess.UserInfo.FamilyName
		user["tenantId"] = sess.TenantID
		user["tenantSlug"] = sess.TenantSlug

		roles := sess.UserInfo.Roles
		if len(sess.UserInfo.RealmAccessRoles) > 0 {
			roles = mergeRoles(roles, sess.UserInfo.RealmAccessRoles)
		}
		user["roles"] = roles
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"user":          user,
		"expiresAt":     sess.ExpiresAt,
		"csrfToken":     sess.CSRFToken,
	})
}

// Refresh refreshes the access token.
func (h *AuthHandler) Refresh(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	app := middleware.GetApp(c)
	if app == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "UNKNOWN_APP"})
		return
	}

	if sess.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "NO_REFRESH_TOKEN"})
		return
	}

	provider, err := h.oidcManager.GetProviderForApp(app)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "OIDC_ERROR"})
		return
	}

	tokens, err := provider.Refresh(c.Request.Context(), sess.RefreshToken)
	if err != nil {
		h.logger.Error("token refresh failed", "error", err, "user_id", sess.UserID)
		// Clear session on refresh failure
		_ = h.store.DeleteSession(c.Request.Context(), sess.ID)
		if app != nil {
			host := middleware.GetEffectiveHost(c)
			domain := middleware.GetCookieDomain(host, app, h.cfg.PlatformDomain)
			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(app.SessionCookie, "", -1, "/", domain, !h.cfg.IsDevelopment(), true)
		}
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "REFRESH_FAILED"})
		return
	}

	sess.AccessToken = tokens.AccessToken
	sess.IDToken = tokens.IDToken
	if tokens.RefreshToken != "" {
		sess.RefreshToken = tokens.RefreshToken
	}
	sess.ExpiresAt = tokens.ExpiresAt.Unix()

	if err := h.store.UpdateSession(c.Request.Context(), sess); err != nil {
		h.logger.Error("update session after refresh", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "SESSION_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"expiresAt": sess.ExpiresAt,
	})
}

// CSRFToken returns the CSRF token from the current session.
func (h *AuthHandler) CSRFToken(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"csrfToken": sess.CSRFToken})
}

// CreateWSTicket creates a short-lived WebSocket authentication ticket.
func (h *AuthHandler) CreateWSTicket(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	ticket := uuid.New().String()
	wsTicket := &session.WSTicket{
		UserID:     sess.UserID,
		TenantID:   sess.TenantID,
		TenantSlug: sess.TenantSlug,
		SessionID:  sess.ID,
	}

	if err := h.store.SaveWSTicket(c.Request.Context(), ticket, wsTicket); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "SESSION_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ticket":    ticket,
		"expiresIn": 30,
	})
}

// SessionTransfer enables cross-app session transfer.
func (h *AuthHandler) SessionTransfer(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	var req struct {
		TargetApp string `json:"targetApp" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	code := uuid.New().String()
	transfer := &session.SessionTransfer{
		SessionID:  sess.ID,
		UserID:     sess.UserID,
		TenantID:   sess.TenantID,
		TenantSlug: sess.TenantSlug,
		SourceApp:  sess.AppName,
		TargetApp:  req.TargetApp,
	}

	if err := h.store.SaveSessionTransfer(c.Request.Context(), code, transfer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "SESSION_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"code":    code,
	})
}

// requireInternalServiceKey validates the X-Internal-Service-Key header
// for service-to-service calls (e.g. Cloud Run → auth-bff via public ingress).
func (h *AuthHandler) requireInternalServiceKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.cfg.InternalServiceKey == "" {
			c.Next()
			return
		}
		key := c.GetHeader("X-Internal-Service-Key")
		if key != h.cfg.InternalServiceKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
			return
		}
		c.Next()
	}
}

// TokenExchange exchanges a session ID for an access token.
// This is the same as InternalHandler.ExchangeToken but exposed under /auth/
// so it's reachable from Cloud Run via the Istio VirtualService /auth route.
func (h *AuthHandler) TokenExchange(c *gin.Context) {
	var req struct {
		SessionID string `json:"sessionId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	sess, err := h.store.GetSession(c.Request.Context(), req.SessionID)
	if err != nil || sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "SESSION_NOT_FOUND"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"access_token": sess.AccessToken,
		"user_id":      sess.UserID,
		"tenant_id":    sess.TenantID,
		"tenant_slug":  sess.TenantSlug,
		"expires_at":   sess.ExpiresAt,
	})
}

// helpers

func (h *AuthHandler) resolveAppFromFlow(flow *session.AuthFlowState) *config.AppConfig {
	for _, app := range h.cfg.Apps {
		if app.Name == flow.AppName {
			return &app
		}
	}
	return nil
}

func clientTypeForRealm(realm string) string {
	if realm == "customers" {
		return "customer"
	}
	return "internal"
}

func sanitizeReturnTo(returnTo string, app *config.AppConfig) string {
	if returnTo == "" {
		return ""
	}
	// Only allow relative paths or same-origin
	parsed, err := url.Parse(returnTo)
	if err != nil {
		return ""
	}
	// Reject absolute URLs with a host
	if parsed.Host != "" {
		return ""
	}
	// Must start with /
	if !strings.HasPrefix(returnTo, "/") {
		return ""
	}
	return returnTo
}

func extractTenantSlug(host string, app *config.AppConfig) string {
	host = strings.ToLower(host)

	if app == nil || app.ProductDomain == "" {
		return ""
	}
	baseDomain := app.ProductDomain

	// Pattern: {slug}-admin.{baseDomain} → slug
	suffix := "-admin." + baseDomain
	if strings.HasSuffix(host, suffix) {
		return strings.TrimSuffix(host, suffix)
	}
	// Pattern: {slug}.{baseDomain} → slug (storefront)
	suffix = "." + baseDomain
	if strings.HasSuffix(host, suffix) {
		slug := strings.TrimSuffix(host, suffix)
		// Exclude known subdomains
		known := map[string]bool{"www": true, "api": true, "auth": true, "onboarding": true, "dev": true}
		if !known[slug] && !strings.Contains(slug, "-admin") && !strings.Contains(slug, "-onboarding") {
			return slug
		}
	}
	return ""
}

func getStringClaim(claims map[string]interface{}, key string) string {
	if claims == nil {
		return ""
	}
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func buildUserInfo(claims map[string]interface{}) *session.UserInfo {
	if claims == nil {
		return nil
	}

	info := &session.UserInfo{
		Sub:              getStringClaim(claims, "sub"),
		Email:            getStringClaim(claims, "email"),
		Name:             getStringClaim(claims, "name"),
		GivenName:        getStringClaim(claims, "given_name"),
		FamilyName:       getStringClaim(claims, "family_name"),
		PreferredUsername: getStringClaim(claims, "preferred_username"),
		TenantID:         getStringClaim(claims, "tenant_id"),
		TenantSlug:       getStringClaim(claims, "tenant_slug"),
	}

	if v, ok := claims["email_verified"].(bool); ok {
		info.EmailVerified = v
	}

	if v, ok := claims["is_platform_owner"].(bool); ok {
		info.IsPlatformOwner = v
	} else if v, ok := claims["platform_owner"].(string); ok {
		info.IsPlatformOwner = v == "true"
	}

	// Extract roles from multiple sources
	if roles, ok := claims["roles"].([]interface{}); ok {
		for _, r := range roles {
			if s, ok := r.(string); ok {
				info.Roles = append(info.Roles, s)
			}
		}
	}
	if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
		if roles, ok := ra["roles"].([]interface{}); ok {
			for _, r := range roles {
				if s, ok := r.(string); ok {
					info.RealmAccessRoles = append(info.RealmAccessRoles, s)
				}
			}
		}
	}

	return info
}

func mergeRoles(a, b []string) []string {
	seen := make(map[string]struct{})
	var merged []string
	for _, r := range a {
		if _, ok := seen[r]; !ok {
			seen[r] = struct{}{}
			merged = append(merged, r)
		}
	}
	for _, r := range b {
		if _, ok := seen[r]; !ok {
			seen[r] = struct{}{}
			merged = append(merged, r)
		}
	}
	return merged
}
