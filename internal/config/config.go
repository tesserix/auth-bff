package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the auth-bff service.
type Config struct {
	Port        string
	Environment string
	ServiceName string

	// Google Identity Platform
	GCPProjectID string
	GIPAPIKey    string // GIP web API key (for client-side flows)

	// Session cookies
	CookieEncryptionKey string // AES-256 key (hex) for encrypted session cookies
	SessionMaxAge       time.Duration
	CookieSecure        bool // Set to true in production (HTTPS only)

	// CSRF
	CSRFSecret string

	// MFA encryption
	EncryptionKey           string // AES key for TOTP secrets (hex)
	BackupCodeHMACKey       string
	TOTPKeyDerivationSecret string

	// Products config
	ProductsConfigPath string
	PlatformDomain     string // From products.yaml

	// WebAuthn
	WebAuthnRPID   string
	WebAuthnRPName string

	// External services (Cloud Run, auto-authenticated via OIDC)
	TenantServiceURL string

	// Internal service auth (for service-to-service calls TO this BFF)
	InternalServiceKey string

	// Rate limiting
	RateLimitRPM int

	// App configurations (populated from products.yaml)
	Apps []AppConfig
}

// AppConfig defines per-application configuration.
// Loaded from products.yaml — one entry per app across all products.
type AppConfig struct {
	Name           string   `yaml:"name" json:"name"`
	Hosts          []string `yaml:"hosts" json:"hosts"`
	GIPTenantID    string   `yaml:"gipTenantId" json:"gipTenantId"`       // GIP tenant ID (e.g., "staff", "customer")
	OAuthClientID  string   `yaml:"oauthClientId" json:"oauthClientId"`   // OAuth 2.0 client ID in GIP
	OAuthClientSecret string `yaml:"-" json:"-"`
	ClientSecretEnv   string `yaml:"clientSecretEnv" json:"-"`
	SessionCookie  string   `yaml:"sessionCookie" json:"sessionCookie"`
	CallbackPath   string   `yaml:"callbackPath" json:"callbackPath"`
	PostLoginURL   string   `yaml:"postLoginUrl" json:"postLoginUrl"`
	PostLogoutURL  string   `yaml:"postLogoutUrl" json:"postLogoutUrl"`
	AllowedOrigins []string `yaml:"allowedOrigins" json:"allowedOrigins"`
	AuthContext    string   `yaml:"authContext" json:"authContext"` // "staff" or "customer"
	AllowedEmails []string `yaml:"allowedEmails" json:"-"`        // Email whitelist (empty = allow all)
	ProductDomain  string   `yaml:"-" json:"-"`
}

// Load reads configuration from environment variables and products.yaml.
func Load() (*Config, error) {
	cfg := &Config{
		Port:        getEnv("PORT", "8080"),
		Environment: getEnv("APP_ENV", "development"),
		ServiceName: "auth-bff",

		GCPProjectID: getEnv("GCP_PROJECT_ID", ""),
		GIPAPIKey:    os.Getenv("GIP_API_KEY"),

		CookieEncryptionKey: os.Getenv("COOKIE_ENCRYPTION_KEY"),
		SessionMaxAge:       getEnvAsDuration("SESSION_MAX_AGE", 24*time.Hour),
		CookieSecure:        getEnv("APP_ENV", "development") == "production",

		CSRFSecret: os.Getenv("CSRF_SECRET"),

		EncryptionKey:           os.Getenv("ENCRYPTION_KEY"),
		BackupCodeHMACKey:       os.Getenv("BACKUP_CODE_HMAC_KEY"),
		TOTPKeyDerivationSecret: os.Getenv("TOTP_KEY_DERIVATION_SECRET"),

		ProductsConfigPath: getEnv("PRODUCTS_CONFIG_PATH", "products.yaml"),

		WebAuthnRPID:   getEnv("WEBAUTHN_RP_ID", "tesserix.app"),
		WebAuthnRPName: getEnv("WEBAUTHN_RP_NAME", "Tesserix"),

		TenantServiceURL: getEnv("TENANT_SERVICE_URL", "http://localhost:8091"),

		InternalServiceKey: os.Getenv("INTERNAL_SERVICE_KEY"),

		RateLimitRPM: getEnvAsInt("RATE_LIMIT_RPM", 300),
	}

	if err := cfg.LoadProducts(); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks that required configuration values are present.
func (c *Config) Validate() error {
	if c.IsProduction() {
		required := map[string]string{
			"COOKIE_ENCRYPTION_KEY": c.CookieEncryptionKey,
			"CSRF_SECRET":          c.CSRFSecret,
			"GCP_PROJECT_ID":       c.GCPProjectID,
		}
		for name, val := range required {
			if val == "" {
				return fmt.Errorf("required env var %s is not set", name)
			}
		}
		if len(c.CookieEncryptionKey) < 32 {
			return fmt.Errorf("COOKIE_ENCRYPTION_KEY must be at least 32 characters")
		}
		if len(c.CSRFSecret) < 32 {
			return fmt.Errorf("CSRF_SECRET must be at least 32 characters")
		}
		for _, app := range c.Apps {
			if app.OAuthClientSecret == "" {
				return fmt.Errorf("client secret for app %q (env: %s) is not set", app.Name, app.ClientSecretEnv)
			}
		}
	}
	return nil
}

// GIPIssuerURL returns the OIDC issuer URL for a GIP tenant.
func (c *Config) GIPIssuerURL(gipTenantID string) string {
	if gipTenantID == "" {
		return fmt.Sprintf("https://securetoken.google.com/%s", c.GCPProjectID)
	}
	return fmt.Sprintf("https://securetoken.google.com/%s", c.GCPProjectID)
}

// IsProduction returns true if running in production.
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsDevelopment returns true if running in development.
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// AllAllowedOrigins returns a flat list of all allowed origins across all apps.
func (c *Config) AllAllowedOrigins() []string {
	seen := make(map[string]struct{})
	var origins []string
	for _, app := range c.Apps {
		for _, o := range app.AllowedOrigins {
			if _, ok := seen[o]; !ok {
				seen[o] = struct{}{}
				origins = append(origins, o)
			}
		}
	}
	return origins
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvAsDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func getEnvAsSlice(key string, fallback []string) []string {
	if v := os.Getenv(key); v != "" {
		parts := strings.Split(v, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	}
	return fallback
}
