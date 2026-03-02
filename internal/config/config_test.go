package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear any env vars that might interfere
	envKeys := []string{"PORT", "APP_ENV", "REDIS_URL", "KEYCLOAK_URL", "SESSION_SECRET", "CSRF_SECRET"}
	for _, k := range envKeys {
		os.Unsetenv(k)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"port", cfg.Port, "8080"},
		{"environment", cfg.Environment, "development"},
		{"service_name", cfg.ServiceName, "auth-bff"},
		{"redis_url", cfg.RedisURL, "redis://localhost:6379"},
		{"keycloak_url", cfg.KeycloakURL, "https://auth.tesserix.app"},
		{"internal_realm", cfg.InternalRealm, "internal"},
		{"customer_realm", cfg.CustomerRealm, "customers"},
		{"base_domain", cfg.BaseDomain, "tesserix.app"},
		{"home_domain", cfg.HomeDomain, "tesserix.app"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("APP_ENV", "staging")
	t.Setenv("REDIS_URL", "redis://custom:6380")
	t.Setenv("BASE_DOMAIN", "mark8ly.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Port != "9090" {
		t.Errorf("Port = %q, want 9090", cfg.Port)
	}
	if cfg.Environment != "staging" {
		t.Errorf("Environment = %q, want staging", cfg.Environment)
	}
	if cfg.RedisURL != "redis://custom:6380" {
		t.Errorf("RedisURL = %q, want redis://custom:6380", cfg.RedisURL)
	}
	if cfg.BaseDomain != "mark8ly.com" {
		t.Errorf("BaseDomain = %q, want mark8ly.com", cfg.BaseDomain)
	}
}

func TestValidate_Production(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*Config)
		wantErr bool
	}{
		{
			name: "missing session secret",
			setup: func(c *Config) {
				c.Environment = "production"
				c.SessionSecret = ""
			},
			wantErr: true,
		},
		{
			name: "short session secret",
			setup: func(c *Config) {
				c.Environment = "production"
				c.SessionSecret = "short"
				c.CSRFSecret = "a]3HQkw@&C!z9yV^BkW#nX2$pL8rJ5mA"
				c.InternalClientSecret = "secret"
				c.CustomerClientSecret = "secret"
				c.EncryptionKey = "key"
				c.BackupCodeHMACKey = "key"
			},
			wantErr: true,
		},
		{
			name: "all required set",
			setup: func(c *Config) {
				c.Environment = "production"
				c.SessionSecret = "a]3HQkw@&C!z9yV^BkW#nX2$pL8rJ5mA"
				c.CSRFSecret = "b]3HQkw@&C!z9yV^BkW#nX2$pL8rJ5mB"
				c.InternalClientSecret = "secret"
				c.CustomerClientSecret = "secret"
				c.EncryptionKey = "key"
				c.BackupCodeHMACKey = "key"
			},
			wantErr: false,
		},
		{
			name: "development allows empty secrets",
			setup: func(c *Config) {
				c.Environment = "development"
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			tt.setup(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsProduction(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"production", true},
		{"staging", false},
		{"development", false},
	}
	for _, tt := range tests {
		cfg := &Config{Environment: tt.env}
		if got := cfg.IsProduction(); got != tt.want {
			t.Errorf("IsProduction(%q) = %v, want %v", tt.env, got, tt.want)
		}
	}
}

func TestIsDevelopment(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"development", true},
		{"production", false},
		{"staging", false},
	}
	for _, tt := range tests {
		cfg := &Config{Environment: tt.env}
		if got := cfg.IsDevelopment(); got != tt.want {
			t.Errorf("IsDevelopment(%q) = %v, want %v", tt.env, got, tt.want)
		}
	}
}

func TestBuildAppConfigs(t *testing.T) {
	cfg := &Config{
		BaseDomain:           "tesserix.app",
		HomeDomain:           "tesserix.app",
		InternalRealm:        "internal",
		CustomerRealm:        "customers",
		InternalClientID:     "admin-bff",
		InternalClientSecret: "sec1",
		CustomerClientID:     "storefront-bff",
		CustomerClientSecret: "sec2",
	}
	apps := cfg.buildAppConfigs()

	if len(apps) != 4 {
		t.Fatalf("got %d apps, want 4", len(apps))
	}

	names := map[string]bool{}
	for _, app := range apps {
		names[app.Name] = true
	}

	for _, expected := range []string{"admin", "storefront", "home", "onboarding"} {
		if !names[expected] {
			t.Errorf("missing app %q", expected)
		}
	}

	// Check admin app
	var admin AppConfig
	for _, app := range apps {
		if app.Name == "admin" {
			admin = app
		}
	}
	if admin.SessionCookie != "bff_session" {
		t.Errorf("admin cookie = %q, want bff_session", admin.SessionCookie)
	}
	if admin.Realm != "internal" {
		t.Errorf("admin realm = %q, want internal", admin.Realm)
	}
	if admin.AuthContext != "staff" {
		t.Errorf("admin auth_context = %q, want staff", admin.AuthContext)
	}

	// Check storefront app
	var storefront AppConfig
	for _, app := range apps {
		if app.Name == "storefront" {
			storefront = app
		}
	}
	if storefront.SessionCookie != "bff_storefront_session" {
		t.Errorf("storefront cookie = %q, want bff_storefront_session", storefront.SessionCookie)
	}
	if storefront.AuthContext != "customer" {
		t.Errorf("storefront auth_context = %q, want customer", storefront.AuthContext)
	}
}

func TestAllAllowedOrigins(t *testing.T) {
	cfg := &Config{
		Apps: []AppConfig{
			{AllowedOrigins: []string{"https://a.com", "https://b.com"}},
			{AllowedOrigins: []string{"https://b.com", "https://c.com"}},
		},
	}

	origins := cfg.AllAllowedOrigins()
	if len(origins) != 3 {
		t.Errorf("got %d origins, want 3 (deduped)", len(origins))
	}
}

func TestGetEnvHelpers(t *testing.T) {
	t.Run("getEnv", func(t *testing.T) {
		os.Unsetenv("TEST_KEY")
		if got := getEnv("TEST_KEY", "default"); got != "default" {
			t.Errorf("getEnv() = %q, want default", got)
		}
		t.Setenv("TEST_KEY", "custom")
		if got := getEnv("TEST_KEY", "default"); got != "custom" {
			t.Errorf("getEnv() = %q, want custom", got)
		}
	})

	t.Run("getEnvAsInt", func(t *testing.T) {
		os.Unsetenv("TEST_INT")
		if got := getEnvAsInt("TEST_INT", 42); got != 42 {
			t.Errorf("getEnvAsInt() = %d, want 42", got)
		}
		t.Setenv("TEST_INT", "100")
		if got := getEnvAsInt("TEST_INT", 42); got != 100 {
			t.Errorf("getEnvAsInt() = %d, want 100", got)
		}
		t.Setenv("TEST_INT", "invalid")
		if got := getEnvAsInt("TEST_INT", 42); got != 42 {
			t.Errorf("getEnvAsInt(invalid) = %d, want 42", got)
		}
	})

	t.Run("getEnvAsDuration", func(t *testing.T) {
		os.Unsetenv("TEST_DUR")
		if got := getEnvAsDuration("TEST_DUR", 5*time.Second); got != 5*time.Second {
			t.Errorf("getEnvAsDuration() = %v, want 5s", got)
		}
		t.Setenv("TEST_DUR", "30s")
		if got := getEnvAsDuration("TEST_DUR", 5*time.Second); got != 30*time.Second {
			t.Errorf("getEnvAsDuration() = %v, want 30s", got)
		}
	})

	t.Run("getEnvAsSlice", func(t *testing.T) {
		os.Unsetenv("TEST_SLICE")
		got := getEnvAsSlice("TEST_SLICE", []string{"a"})
		if len(got) != 1 || got[0] != "a" {
			t.Errorf("getEnvAsSlice() = %v, want [a]", got)
		}
		t.Setenv("TEST_SLICE", "x, y, z")
		got = getEnvAsSlice("TEST_SLICE", nil)
		if len(got) != 3 || got[1] != "y" {
			t.Errorf("getEnvAsSlice() = %v, want [x y z]", got)
		}
	})
}
