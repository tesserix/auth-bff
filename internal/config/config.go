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
	RedisURL string

	// Keycloak
	KeycloakURL          string
	KeycloakInternalURL  string // Optional: internal URL for server-to-server calls (bypass CDN)
	InternalRealm        string
	CustomerRealm        string
	InternalClientID     string
	InternalClientSecret string
	CustomerClientID     string
	CustomerClientSecret string

	// Session
	SessionSecret string
	SessionMaxAge time.Duration

	// CSRF
	CSRFSecret string

	// Encryption
	EncryptionKey          string // AES key for TOTP secrets (hex)
	BackupCodeHMACKey      string
	TOTPKeyDerivationSecret string

	// Domains
	BaseDomain string
	HomeDomain string

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

	// App configurations (populated from above)
	Apps []AppConfig
}

// AppConfig defines per-application configuration.
type AppConfig struct {
	Name           string   `json:"name"`
	Hosts          []string `json:"hosts"`
	Realm          string   `json:"realm"`
	ClientID       string   `json:"clientId"`
	ClientSecret   string   `json:"clientSecret"`
	SessionCookie  string   `json:"sessionCookie"`
	CallbackPath   string   `json:"callbackPath"`
	PostLoginURL   string   `json:"postLoginUrl"`
	PostLogoutURL  string   `json:"postLogoutUrl"`
	AllowedOrigins []string `json:"allowedOrigins"`
	AuthContext    string   `json:"authContext"` // "staff" or "customer"
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		Port:        getEnv("PORT", "8080"),
		Environment: getEnv("APP_ENV", "development"),
		ServiceName: "auth-bff",

		RedisURL: getEnv("REDIS_URL", "redis://localhost:6379"),

		KeycloakURL:          getEnv("KEYCLOAK_URL", "https://auth.tesserix.app"),
		KeycloakInternalURL:  getEnv("KEYCLOAK_INTERNAL_URL", ""),
		InternalRealm:        getEnv("INTERNAL_REALM", "internal"),
		CustomerRealm:        getEnv("CUSTOMER_REALM", "customers"),
		InternalClientID:     getEnv("INTERNAL_CLIENT_ID", "admin-bff"),
		InternalClientSecret: os.Getenv("INTERNAL_CLIENT_SECRET"),
		CustomerClientID:     getEnv("CUSTOMER_CLIENT_ID", "storefront-bff"),
		CustomerClientSecret: os.Getenv("CUSTOMER_CLIENT_SECRET"),

		SessionSecret: os.Getenv("SESSION_SECRET"),
		SessionMaxAge: getEnvAsDuration("SESSION_MAX_AGE", 24*time.Hour),

		CSRFSecret: os.Getenv("CSRF_SECRET"),

		EncryptionKey:          os.Getenv("ENCRYPTION_KEY"),
		BackupCodeHMACKey:      os.Getenv("BACKUP_CODE_HMAC_KEY"),
		TOTPKeyDerivationSecret: os.Getenv("TOTP_KEY_DERIVATION_SECRET"),

		BaseDomain: getEnv("BASE_DOMAIN", "tesserix.app"),
		HomeDomain: getEnv("HOME_DOMAIN", "tesserix.app"),

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

	cfg.Apps = cfg.buildAppConfigs()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// buildAppConfigs constructs per-app configurations from the top-level config.
func (c *Config) buildAppConfigs() []AppConfig {
	return []AppConfig{
		{
			Name:          "admin",
			Hosts:         c.adminHosts(),
			Realm:         c.InternalRealm,
			ClientID:      c.InternalClientID,
			ClientSecret:  c.InternalClientSecret,
			SessionCookie: "bff_session",
			CallbackPath:  "/auth/callback",
			PostLoginURL:  "/",
			PostLogoutURL: "/login",
			AllowedOrigins: c.adminOrigins(),
			AuthContext:   "staff",
		},
		{
			Name:          "storefront",
			Hosts:         c.storefrontHosts(),
			Realm:         c.CustomerRealm,
			ClientID:      c.CustomerClientID,
			ClientSecret:  c.CustomerClientSecret,
			SessionCookie: "bff_storefront_session",
			CallbackPath:  "/auth/callback",
			PostLoginURL:  "/",
			PostLogoutURL: "/",
			AllowedOrigins: c.storefrontOrigins(),
			AuthContext:   "customer",
		},
		{
			Name:          "home",
			Hosts:         c.homeHosts(),
			Realm:         c.InternalRealm,
			ClientID:      c.InternalClientID,
			ClientSecret:  c.InternalClientSecret,
			SessionCookie: "bff_home_session",
			CallbackPath:  "/api/auth/callback",
			PostLoginURL:  "/",
			PostLogoutURL: "/login",
			AllowedOrigins: c.homeOrigins(),
			AuthContext:   "staff",
		},
		{
			Name:          "onboarding",
			Hosts:         c.onboardingHosts(),
			Realm:         c.InternalRealm,
			ClientID:      c.InternalClientID,
			ClientSecret:  c.InternalClientSecret,
			SessionCookie: "bff_session",
			CallbackPath:  "/auth/callback",
			PostLoginURL:  "/",
			PostLogoutURL: "/login",
			AllowedOrigins: c.onboardingOrigins(),
			AuthContext:   "staff",
		},
	}
}

func (c *Config) adminHosts() []string {
	return []string{
		"*-admin." + c.BaseDomain,
		"admin.localhost",
		"localhost:3000",
	}
}

func (c *Config) storefrontHosts() []string {
	return []string{
		"*." + c.BaseDomain,
	}
}

func (c *Config) homeHosts() []string {
	return []string{
		c.HomeDomain,
		"www." + c.HomeDomain,
		"company." + c.HomeDomain,
		"localhost:3002",
	}
}

func (c *Config) onboardingHosts() []string {
	return []string{
		"onboarding." + c.BaseDomain,
		"*-onboarding." + c.BaseDomain,
		"localhost:3001",
	}
}

func (c *Config) adminOrigins() []string {
	return []string{
		"https://*-admin." + c.BaseDomain,
		"http://localhost:3000",
	}
}

func (c *Config) storefrontOrigins() []string {
	return []string{
		"https://*." + c.BaseDomain,
	}
}

func (c *Config) homeOrigins() []string {
	return []string{
		"https://" + c.HomeDomain,
		"https://www." + c.HomeDomain,
		"https://company." + c.HomeDomain,
		"http://localhost:3002",
	}
}

func (c *Config) onboardingOrigins() []string {
	return []string{
		"https://onboarding." + c.BaseDomain,
		"https://*-onboarding." + c.BaseDomain,
		"http://localhost:3001",
	}
}

// Validate checks that required configuration values are present.
func (c *Config) Validate() error {
	if c.IsProduction() {
		required := map[string]string{
			"SESSION_SECRET":          c.SessionSecret,
			"CSRF_SECRET":             c.CSRFSecret,
			"INTERNAL_CLIENT_SECRET":  c.InternalClientSecret,
			"CUSTOMER_CLIENT_SECRET":  c.CustomerClientSecret,
			"ENCRYPTION_KEY":          c.EncryptionKey,
			"BACKUP_CODE_HMAC_KEY":    c.BackupCodeHMACKey,
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
	}
	return nil
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
