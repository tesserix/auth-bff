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

	// Redis
	RedisURL      string
	RedisPassword string

	// Keycloak base URLs (shared across all realms)
	KeycloakURL                string
	KeycloakInternalURL        string // Optional: internal URL for server-to-server calls (bypass CDN)
	CustomerKeycloakURL        string // Optional: separate public URL for customer realm
	CustomerKeycloakInternalURL string // Optional: separate internal URL for customer realm
	InternalRealm              string // Realm name for internal/staff apps
	CustomerRealm              string // Realm name for customer-facing apps

	// Session
	SessionSecret string
	SessionMaxAge time.Duration

	// CSRF
	CSRFSecret string

	// Encryption
	EncryptionKey           string // AES key for TOTP secrets (hex)
	BackupCodeHMACKey       string
	TOTPKeyDerivationSecret string

	// Products config
	ProductsConfigPath string // Path to products.yaml (default: "products.yaml")
	PlatformDomain     string // From products.yaml — used for WebAuthn RP ID and cross-product cookies

	// WebAuthn
	WebAuthnRPID   string
	WebAuthnRPName string

	// External services
	TenantServiceURL       string
	VerificationServiceURL string
	VerificationAPIKey     string
	APIGatewayURL          string

	// NATS
	NATSURL string

	// GCP
	GCPProjectID string

	// Internal service auth
	InternalServiceKey string

	// Rate limiting
	RateLimitRPM int

	// App configurations (populated from products.yaml)
	Apps []AppConfig
}

// AppConfig defines per-application configuration.
// Loaded from products.yaml — one entry per app across all products.
type AppConfig struct {
	Name            string   `yaml:"name" json:"name"`
	Hosts           []string `yaml:"hosts" json:"hosts"`
	Realm           string   `yaml:"realm" json:"realm"`
	ClientID        string   `yaml:"clientId" json:"clientId"`
	ClientSecret    string   `yaml:"-" json:"-"`
	ClientSecretEnv string   `yaml:"clientSecretEnv" json:"-"`
	SessionCookie   string   `yaml:"sessionCookie" json:"sessionCookie"`
	CallbackPath    string   `yaml:"callbackPath" json:"callbackPath"`
	PostLoginURL    string   `yaml:"postLoginUrl" json:"postLoginUrl"`
	PostLogoutURL   string   `yaml:"postLogoutUrl" json:"postLogoutUrl"`
	AllowedOrigins  []string `yaml:"allowedOrigins" json:"allowedOrigins"`
	AuthContext     string   `yaml:"authContext" json:"authContext"` // "staff" or "customer"
	ProductDomain   string   `yaml:"-" json:"-"`                    // Set from parent product
}

// Load reads configuration from environment variables and products.yaml.
func Load() (*Config, error) {
	cfg := &Config{
		Port:        getEnv("PORT", "8080"),
		Environment: getEnv("APP_ENV", "development"),
		ServiceName: "auth-bff",

		RedisURL:      getEnv("REDIS_URL", "redis://localhost:6379"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),

		KeycloakURL:                 getEnv("KEYCLOAK_URL", "https://auth.tesserix.app"),
		KeycloakInternalURL:         getEnv("KEYCLOAK_INTERNAL_URL", ""),
		CustomerKeycloakURL:         getEnv("CUSTOMER_KEYCLOAK_URL", ""),
		CustomerKeycloakInternalURL: getEnv("CUSTOMER_KEYCLOAK_INTERNAL_URL", ""),
		InternalRealm:               getEnv("INTERNAL_REALM", "internal"),
		CustomerRealm:               getEnv("CUSTOMER_REALM", "customers"),

		SessionSecret: os.Getenv("SESSION_SECRET"),
		SessionMaxAge: getEnvAsDuration("SESSION_MAX_AGE", 24*time.Hour),

		CSRFSecret: os.Getenv("CSRF_SECRET"),

		EncryptionKey:           os.Getenv("ENCRYPTION_KEY"),
		BackupCodeHMACKey:       os.Getenv("BACKUP_CODE_HMAC_KEY"),
		TOTPKeyDerivationSecret: os.Getenv("TOTP_KEY_DERIVATION_SECRET"),

		ProductsConfigPath: getEnv("PRODUCTS_CONFIG_PATH", "products.yaml"),

		WebAuthnRPID:   getEnv("WEBAUTHN_RP_ID", "tesserix.app"),
		WebAuthnRPName: getEnv("WEBAUTHN_RP_NAME", "Tesserix"),

		TenantServiceURL:       getEnv("TENANT_SERVICE_URL", "http://tenant-service:8091"),
		VerificationServiceURL: getEnv("VERIFICATION_SERVICE_URL", ""),
		VerificationAPIKey:     os.Getenv("VERIFICATION_SERVICE_API_KEY"),
		APIGatewayURL:          getEnv("API_GATEWAY_URL", "http://api-gateway:8080"),

		NATSURL: getEnv("NATS_URL", "nats://nats.nats:4222"),

		GCPProjectID: getEnv("GCP_PROJECT_ID", ""),

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
			"SESSION_SECRET":    c.SessionSecret,
			"CSRF_SECRET":       c.CSRFSecret,
			"ENCRYPTION_KEY":    c.EncryptionKey,
			"BACKUP_CODE_HMAC_KEY": c.BackupCodeHMACKey,
		}
		for name, val := range required {
			if val == "" {
				return fmt.Errorf("required env var %s is not set", name)
			}
		}
		if len(c.SessionSecret) < 32 {
			return fmt.Errorf("SESSION_SECRET must be at least 32 characters")
		}
		if len(c.CSRFSecret) < 32 {
			return fmt.Errorf("CSRF_SECRET must be at least 32 characters")
		}
		// Validate that all apps have their client secrets resolved
		for _, app := range c.Apps {
			if app.ClientSecret == "" {
				return fmt.Errorf("client secret for app %q (env: %s) is not set", app.Name, app.ClientSecretEnv)
			}
		}
	}
	return nil
}

// CustomerKeycloakPublicURL returns the public Keycloak URL for the customer realm.
// Falls back to the shared KeycloakURL if not set.
func (c *Config) CustomerKeycloakPublicURL() string {
	if c.CustomerKeycloakURL != "" {
		return c.CustomerKeycloakURL
	}
	return c.KeycloakURL
}

// CustomerKeycloakDiscoveryURL returns the internal Keycloak URL for the customer realm.
// Falls back to the shared KeycloakInternalURL if not set.
func (c *Config) CustomerKeycloakDiscoveryURL() string {
	if c.CustomerKeycloakInternalURL != "" {
		return c.CustomerKeycloakInternalURL
	}
	return c.KeycloakInternalURL
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
