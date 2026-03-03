package handlers

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tesserix/auth-bff/internal/clients"
	"github.com/tesserix/go-shared/logger"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/middleware"
	"github.com/tesserix/auth-bff/internal/oidc"
	"github.com/tesserix/auth-bff/internal/session"
)

// ProxyHandler handles API proxy requests with session→JWT injection.
type ProxyHandler struct {
	cfg          *config.Config
	store        session.Store
	oidcManager  *oidc.Manager
	tenantClient *clients.TenantClient
	logger       *logger.Logger
}

// NewProxyHandler creates a new ProxyHandler.
func NewProxyHandler(cfg *config.Config, store session.Store, oidcMgr *oidc.Manager, tc *clients.TenantClient, logger *logger.Logger) *ProxyHandler {
	return &ProxyHandler{
		cfg:          cfg,
		store:        store,
		oidcManager:  oidcMgr,
		tenantClient: tc,
		logger:       logger,
	}
}

// RegisterRoutes registers the API proxy catch-all route.
func (h *ProxyHandler) RegisterRoutes(r *gin.Engine) {
	// Single catch-all for /api/* with internal dispatch to avoid Gin route conflicts.
	r.Any("/api/*path", middleware.SessionExtractor(h.store), middleware.RequireSession(), h.dispatch)
}

// dispatch routes specific API paths to dedicated handlers, falling back to the proxy.
func (h *ProxyHandler) dispatch(c *gin.Context) {
	path := c.Param("path")
	switch {
	case c.Request.Method == http.MethodGet && path == "/tenants/user-tenants":
		h.UserTenants(c)
	case c.Request.Method == http.MethodPut && path == "/tenants/set-default":
		h.SetDefaultTenant(c)
	default:
		h.Proxy(c)
	}
}

// Proxy forwards authenticated requests to the API gateway with JWT injection.
func (h *ProxyHandler) Proxy(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	// CSRF check for state-changing methods
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead && c.Request.Method != http.MethodOptions {
		csrfToken := c.GetHeader("X-CSRF-Token")
		if csrfToken == "" {
			csrfToken = c.PostForm("_csrf")
		}
		if csrfToken != sess.CSRFToken {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "CSRF_VALIDATION_FAILED"})
			return
		}
	}

	// Auto-refresh tokens if close to expiry (60s buffer)
	if time.Now().Unix()+60 > sess.ExpiresAt && sess.RefreshToken != "" {
		h.refreshSession(c, sess)
	}

	// Build target URL
	target, err := url.Parse(h.cfg.APIGatewayURL)
	if err != nil {
		h.logger.Error("parse api gateway url", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "PROXY_ERROR"})
		return
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = c.Request.URL.Path
			req.URL.RawQuery = c.Request.URL.RawQuery

			// Inject Bearer token
			req.Header.Set("Authorization", "Bearer "+sess.AccessToken)

			// Inject Istio-compatible JWT claim headers
			h.injectClaimHeaders(req, sess)

			// Forward identifying headers
			req.Header.Set("X-Request-ID", c.GetHeader("X-Request-ID"))
			if req.Header.Get("X-Request-ID") == "" {
				req.Header.Set("X-Request-ID", c.Writer.Header().Get("X-Request-ID"))
			}

			// Remove hop-by-hop headers
			req.Header.Del("Cookie")
			req.Header.Del("X-CSRF-Token")
		},
		ModifyResponse: func(resp *http.Response) error {
			// If upstream returns 401, try to refresh and retry
			if resp.StatusCode == http.StatusUnauthorized {
				h.logger.Warn("upstream 401, token may be expired", "user_id", sess.UserID)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.logger.Error("proxy error", "error", err, "path", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(gin.H{
				"success": false,
				"error":   "PROXY_ERROR",
				"message": "Unable to reach upstream service",
			})
		},
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

// UserTenants proxies the user-tenants request to tenant-service directly.
func (h *ProxyHandler) UserTenants(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	// Auto-refresh if needed
	if time.Now().Unix()+60 > sess.ExpiresAt && sess.RefreshToken != "" {
		h.refreshSession(c, sess)
	}

	// Call tenant-service directly
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet,
		h.cfg.TenantServiceURL+"/api/v1/tenants/user-tenants", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "PROXY_ERROR"})
		return
	}

	// Set Istio-style headers from session
	h.setIstioHeaders(req, sess)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.logger.Error("user-tenants request", "error", err)
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "SERVICE_UNAVAILABLE"})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
}

// SetDefaultTenant sets the default tenant for the user.
func (h *ProxyHandler) SetDefaultTenant(c *gin.Context) {
	sess := middleware.GetSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "UNAUTHORIZED"})
		return
	}

	// CSRF check
	csrfToken := c.GetHeader("X-CSRF-Token")
	if csrfToken != sess.CSRFToken {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "CSRF_VALIDATION_FAILED"})
		return
	}

	var req struct {
		TenantID string `json:"tenantId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "INVALID_REQUEST"})
		return
	}

	// Forward to tenant-service
	body := strings.NewReader(`{"tenant_id":"` + req.TenantID + `"}`)
	proxyReq, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPut,
		h.cfg.TenantServiceURL+"/api/v1/tenants/set-default", body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "PROXY_ERROR"})
		return
	}
	proxyReq.Header.Set("Content-Type", "application/json")
	h.setIstioHeaders(proxyReq, sess)

	resp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "SERVICE_UNAVAILABLE"})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
}

// injectClaimHeaders adds Istio-compatible JWT claim headers to the proxy request.
func (h *ProxyHandler) injectClaimHeaders(req *http.Request, sess *session.Session) {
	// Decode JWT to extract claims
	claims := decodeJWTPayload(sess.AccessToken)
	if claims == nil {
		return
	}

	if sub, ok := claims["sub"].(string); ok {
		req.Header.Set("x-jwt-claim-sub", sub)
	}
	if tenantID, ok := claims["tenant_id"].(string); ok {
		req.Header.Set("x-jwt-claim-tenant-id", tenantID)
	} else if sess.TenantID != "" {
		req.Header.Set("x-jwt-claim-tenant-id", sess.TenantID)
	}
	if tenantSlug, ok := claims["tenant_slug"].(string); ok {
		req.Header.Set("x-jwt-claim-tenant-slug", tenantSlug)
	} else if sess.TenantSlug != "" {
		req.Header.Set("x-jwt-claim-tenant-slug", sess.TenantSlug)
	}
	if email, ok := claims["email"].(string); ok {
		req.Header.Set("x-jwt-claim-email", email)
	}
	if name, ok := claims["preferred_username"].(string); ok {
		req.Header.Set("x-jwt-claim-preferred-username", name)
	}

	// Platform owner flag
	if po, ok := claims["platform_owner"].(string); ok && po == "true" {
		req.Header.Set("x-jwt-claim-platform-owner", "true")
	}
}

// setIstioHeaders sets Istio-compatible headers for direct service-to-service calls.
func (h *ProxyHandler) setIstioHeaders(req *http.Request, sess *session.Session) {
	claims := decodeJWTPayload(sess.AccessToken)
	if claims == nil {
		// Fallback to session data
		req.Header.Set("x-jwt-claim-sub", sess.UserID)
		req.Header.Set("x-jwt-claim-tenant-id", sess.TenantID)
		req.Header.Set("x-jwt-claim-tenant-slug", sess.TenantSlug)
		req.Header.Set("x-jwt-claim-email", sess.Email)
		return
	}

	h.injectClaimHeaders(req, sess)
}

// refreshSession attempts to refresh the session tokens.
func (h *ProxyHandler) refreshSession(c *gin.Context, sess *session.Session) {
	app := middleware.GetApp(c)
	if app == nil {
		return
	}

	provider, err := h.oidcManager.GetProviderForApp(app)
	if err != nil {
		return
	}

	tokens, err := provider.Refresh(c.Request.Context(), sess.RefreshToken)
	if err != nil {
		h.logger.Warn("auto-refresh failed", "error", err, "user_id", sess.UserID)
		return
	}

	sess.AccessToken = tokens.AccessToken
	sess.IDToken = tokens.IDToken
	if tokens.RefreshToken != "" {
		sess.RefreshToken = tokens.RefreshToken
	}
	sess.ExpiresAt = tokens.ExpiresAt.Unix()
	_ = h.store.UpdateSession(c.Request.Context(), sess)
}

// decodeJWTPayload extracts claims from a JWT without verification.
// This is safe because we already verified the token during login/refresh.
func decodeJWTPayload(tokenStr string) map[string]interface{} {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims
}
