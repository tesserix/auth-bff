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
	ContextKeySession = "bff_session"
	ContextKeyApp     = "bff_app"
)

// AppResolver injects the resolved AppConfig into the request context
// based on the x-forwarded-host header.
func AppResolver(registry *appregistry.Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		host := c.GetHeader("x-forwarded-host")
		if host == "" {
			host = c.Request.Host
		}

		app := registry.Resolve(host)
		if app != nil {
			c.Set(ContextKeyApp, app)
		}
		c.Next()
	}
}

// SessionExtractor reads the session cookie and loads the session from the store.
// It does NOT abort on missing session — downstream handlers decide auth requirements.
func SessionExtractor(store session.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		app := GetApp(c)
		if app == nil {
			c.Next()
			return
		}

		cookieValue, err := c.Cookie(app.SessionCookie)
		if err != nil || cookieValue == "" {
			c.Next()
			return
		}

		// The cookie value is the session ID
		sess, err := store.GetSession(c.Request.Context(), cookieValue)
		if err != nil {
			// Session expired or not found — clear the cookie
			clearSessionCookie(c, app)
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
				"success": false,
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

// GetEffectiveHost returns the effective external host from the request.
func GetEffectiveHost(c *gin.Context) string {
	host := c.GetHeader("x-forwarded-host")
	if host == "" {
		host = c.Request.Host
	}
	// Handle comma-separated multi-proxy chains
	if idx := strings.IndexByte(host, ','); idx != -1 {
		host = strings.TrimSpace(host[:idx])
	}
	return host
}

// GetCookieDomain determines the cookie domain from the request host.
func GetCookieDomain(host, baseDomain, homeDomain string) string {
	host = strings.ToLower(host)

	// Localhost: no domain (browser defaults)
	if strings.HasPrefix(host, "localhost") {
		return ""
	}

	// Platform domains: set cross-subdomain cookie
	if strings.HasSuffix(host, "."+baseDomain) || host == baseDomain {
		return "." + baseDomain
	}
	if strings.HasSuffix(host, "."+homeDomain) || host == homeDomain {
		return "." + homeDomain
	}

	// Custom domains: strip www, set parent domain
	if strings.HasPrefix(host, "www.") {
		host = host[4:]
	}
	return "." + host
}

func clearSessionCookie(c *gin.Context, app *config.AppConfig) {
	host := GetEffectiveHost(c)
	// We don't know baseDomain/homeDomain here, so just clear with empty domain
	c.SetCookie(app.SessionCookie, "", -1, "/", "", false, true)
	_ = host // Used for domain calculation when we have config access
}
