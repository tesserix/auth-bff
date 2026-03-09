package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tesserix/auth-bff/internal/appregistry"
	"github.com/tesserix/auth-bff/internal/config"
	"github.com/tesserix/auth-bff/internal/session"
)

const (
	ContextKeySession  = "bff_session"
	ContextKeyApp      = "bff_app"
	ContextKeyRegistry = "bff_registry"
)

// AppResolver injects the resolved AppConfig into the request context
// based on the x-forwarded-host header.
func AppResolver(registry *appregistry.Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ContextKeyRegistry, registry)

		host := c.GetHeader("x-forwarded-host")
		if host == "" {
			host = c.Request.Host
		}

		app := registry.Resolve(host)
		if app == nil {
			app = resolveAppFromTenantHeaders(c, registry, host)
		}
		if app != nil {
			c.Set(ContextKeyApp, app)
		}
		c.Next()
	}
}

func resolveAppFromTenantHeaders(c *gin.Context, registry *appregistry.Registry, host string) *config.AppConfig {
	host = strings.ToLower(strings.TrimSpace(host))
	path := strings.ToLower(strings.TrimSpace(c.Request.URL.Path))
	if !strings.HasPrefix(path, "/auth") {
		return nil
	}

	if tenantID := strings.TrimSpace(c.GetHeader("X-Tenant-ID")); tenantID != "" {
		targetType := strings.ToLower(strings.TrimSpace(c.GetHeader("X-Target-Type")))
		switch targetType {
		case "admin", "staff":
			return registry.ResolveByName("admin")
		case "storefront", "customer", "store":
			return registry.ResolveByName("storefront")
		}

		if strings.HasSuffix(host, "-admin.mark8ly.com") {
			return registry.ResolveByName("admin")
		}
		if strings.HasSuffix(host, "-store.mark8ly.com") {
			return registry.ResolveByName("storefront")
		}
		if strings.HasSuffix(host, ".mark8ly.com") {
			return registry.ResolveByName("storefront")
		}

		return registry.ResolveByName("admin")
	}

	return nil
}

// SessionExtractor reads and decrypts the session from the cookie.
// Does NOT abort on missing session — downstream handlers decide auth requirements.
func SessionExtractor(store *session.CookieStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		app := GetApp(c)
		if app == nil {
			c.Next()
			return
		}

		sess, err := store.Load(c, app.SessionCookie)
		if err != nil {
			c.Next()
			return
		}

		c.Set(ContextKeySession, sess)
		c.Next()
	}
}

// RequireSession aborts with 401 if no valid session exists.
func RequireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		if GetSession(c) == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "UNAUTHORIZED",
				"message": "Authentication required",
			})
			return
		}
		c.Next()
	}
}

// GetSession returns the session from the gin context, or nil.
func GetSession(c *gin.Context) *session.Session {
	v, ok := c.Get(ContextKeySession)
	if !ok {
		return nil
	}
	s, _ := v.(*session.Session)
	return s
}

// GetApp returns the resolved AppConfig from the gin context, or nil.
func GetApp(c *gin.Context) *config.AppConfig {
	v, ok := c.Get(ContextKeyApp)
	if !ok {
		return nil
	}
	a, _ := v.(*config.AppConfig)
	return a
}

// GetAppByName returns an AppConfig by name from the registry in context.
func GetAppByName(c *gin.Context, name string) *config.AppConfig {
	v, ok := c.Get(ContextKeyRegistry)
	if !ok {
		return nil
	}
	reg, _ := v.(*appregistry.Registry)
	if reg == nil {
		return nil
	}
	return reg.ResolveByName(name)
}

// GetEffectiveHost returns the effective external host from the request.
func GetEffectiveHost(c *gin.Context) string {
	host := c.GetHeader("x-forwarded-host")
	if host == "" {
		host = c.Request.Host
	}
	if idx := strings.IndexByte(host, ','); idx != -1 {
		host = strings.TrimSpace(host[:idx])
	}
	return host
}

// GetCookieDomain determines the cookie domain from the request host.
func GetCookieDomain(host string, app *config.AppConfig, platformDomain string) string {
	host = strings.ToLower(host)

	if strings.HasPrefix(host, "localhost") {
		return ""
	}

	if app != nil && app.ProductDomain != "" {
		d := app.ProductDomain
		if strings.HasSuffix(host, "."+d) || host == d {
			return "." + d
		}
	}

	if platformDomain != "" {
		if strings.HasSuffix(host, "."+platformDomain) || host == platformDomain {
			return "." + platformDomain
		}
	}

	if strings.HasPrefix(host, "www.") {
		host = host[4:]
	}
	return "." + host
}

// ExtractBearerToken extracts the token from Authorization: Bearer <token>.
func ExtractBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}
