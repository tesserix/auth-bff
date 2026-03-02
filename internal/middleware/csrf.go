package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CSRFProtection validates the CSRF token for state-changing requests.
// Uses double-submit cookie pattern: token in session must match X-CSRF-Token header.
func CSRFProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip safe methods
		if c.Request.Method == http.MethodGet ||
			c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		sess := GetSession(c)
		if sess == nil {
			// No session = no CSRF check needed (the endpoint auth will handle it)
			c.Next()
			return
		}

		// Check header first, then body param
		token := c.GetHeader("X-CSRF-Token")
		if token == "" {
			token = c.PostForm("_csrf")
		}

		if token == "" || token != sess.CSRFToken {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   "CSRF_VALIDATION_FAILED",
				"message": "Invalid or missing CSRF token",
			})
			return
		}

		c.Next()
	}
}
