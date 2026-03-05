package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestProductsYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "products.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test products.yaml: %v", err)
	}
	return path
}

const testProductsYAML = `
platformDomain: tesserix.app
products:
  - name: tesserix
    domain: tesserix.app
    apps:
      - name: home
        hosts:
          - "tesserix.app"
          - "www.tesserix.app"
          - "dev.tesserix.app"
          - "localhost:3002"
        gipTenantId: staff
        oauthClientId: platform-client
        clientSecretEnv: PLATFORM_CLIENT_SECRET
        sessionCookie: bff_home_session
        callbackPath: /auth/callback
        postLoginUrl: /admin/dashboard
        postLogoutUrl: /login
        authContext: staff
        allowedOrigins:
          - "https://tesserix.app"
          - "https://www.tesserix.app"
          - "https://dev.tesserix.app"
          - "http://localhost:3002"
`

func TestLoad_WithProducts(t *testing.T) {
	path := writeTestProductsYAML(t, testProductsYAML)
	t.Setenv("PRODUCTS_CONFIG_PATH", path)
	t.Setenv("PLATFORM_CLIENT_SECRET", "test-secret")

	for _, k := range []string{"PORT", "APP_ENV"} {
		os.Unsetenv(k)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.PlatformDomain != "tesserix.app" {
		t.Errorf("PlatformDomain = %q, want tesserix.app", cfg.PlatformDomain)
	}

	if len(cfg.Apps) != 1 {
		t.Fatalf("got %d apps, want 1", len(cfg.Apps))
	}

	app := cfg.Apps[0]
	if app.Name != "home" {
		t.Errorf("app name = %q, want home", app.Name)
	}
	if app.GIPTenantID != "staff" {
		t.Errorf("gipTenantId = %q, want staff", app.GIPTenantID)
	}
	if app.OAuthClientID != "platform-client" {
		t.Errorf("oauthClientId = %q, want platform-client", app.OAuthClientID)
	}
	if app.OAuthClientSecret != "test-secret" {
		t.Errorf("oauthClientSecret not resolved from env")
	}
	if app.ProductDomain != "tesserix.app" {
		t.Errorf("ProductDomain = %q, want tesserix.app", app.ProductDomain)
	}
	if app.SessionCookie != "bff_home_session" {
		t.Errorf("sessionCookie = %q, want bff_home_session", app.SessionCookie)
	}
	if app.PostLoginURL != "/admin/dashboard" {
		t.Errorf("postLoginUrl = %q, want /admin/dashboard", app.PostLoginURL)
	}
	if len(app.Hosts) != 4 {
		t.Errorf("hosts count = %d, want 4", len(app.Hosts))
	}
}

func TestLoad_Defaults(t *testing.T) {
	path := writeTestProductsYAML(t, testProductsYAML)
	t.Setenv("PRODUCTS_CONFIG_PATH", path)
	t.Setenv("PLATFORM_CLIENT_SECRET", "test-secret")

	for _, k := range []string{"PORT", "APP_ENV"} {
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
		{"platform_domain", cfg.PlatformDomain, "tesserix.app"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestLoad_MissingProductsFile(t *testing.T) {
	t.Setenv("PRODUCTS_CONFIG_PATH", "/nonexistent/products.yaml")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing products file")
	}
}

func TestLoad_NoApps(t *testing.T) {
	yaml := `
platformDomain: tesserix.app
products: []
`
	path := writeTestProductsYAML(t, yaml)
	t.Setenv("PRODUCTS_CONFIG_PATH", path)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for no apps")
	}
}

func TestLoad_MissingPlatformDomain(t *testing.T) {
	yaml := `
products:
  - name: test
    domain: test.com
    apps:
      - name: app1
        hosts: ["localhost"]
        gipTenantId: staff
        oauthClientId: test
        clientSecretEnv: TEST_SECRET
        sessionCookie: test_session
        callbackPath: /callback
        postLoginUrl: /
        postLogoutUrl: /login
        authContext: staff
`
	path := writeTestProductsYAML(t, yaml)
	t.Setenv("PRODUCTS_CONFIG_PATH", path)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing platformDomain")
	}
}

func TestValidate_Production(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*Config)
		wantErr bool
	}{
		{
			name: "missing cookie encryption key",
			setup: func(c *Config) {
				c.Environment = "production"
				c.CookieEncryptionKey = ""
			},
			wantErr: true,
		},
		{
			name: "short cookie encryption key",
			setup: func(c *Config) {
				c.Environment = "production"
				c.CookieEncryptionKey = "short"
				c.CSRFSecret = "a]3HQkw@&C!z9yV^BkW#nX2$pL8rJ5mA"
				c.GCPProjectID = "test-project"
				c.Apps = []AppConfig{{Name: "home", OAuthClientSecret: "sec", ClientSecretEnv: "X"}}
			},
			wantErr: true,
		},
		{
			name: "all required set",
			setup: func(c *Config) {
				c.Environment = "production"
				c.CookieEncryptionKey = "a]3HQkw@&C!z9yV^BkW#nX2$pL8rJ5mA"
				c.CSRFSecret = "b]3HQkw@&C!z9yV^BkW#nX2$pL8rJ5mB"
				c.GCPProjectID = "test-project"
				c.Apps = []AppConfig{{Name: "home", OAuthClientSecret: "sec", ClientSecretEnv: "X"}}
			},
			wantErr: false,
		},
		{
			name: "missing app client secret in production",
			setup: func(c *Config) {
				c.Environment = "production"
				c.CookieEncryptionKey = "a]3HQkw@&C!z9yV^BkW#nX2$pL8rJ5mA"
				c.CSRFSecret = "b]3HQkw@&C!z9yV^BkW#nX2$pL8rJ5mB"
				c.GCPProjectID = "test-project"
				c.Apps = []AppConfig{{Name: "home", OAuthClientSecret: "", ClientSecretEnv: "MISSING_ENV"}}
			},
			wantErr: true,
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

func TestGIPIssuerURL(t *testing.T) {
	cfg := &Config{GCPProjectID: "my-project"}

	url := cfg.GIPIssuerURL("staff")
	if url != "https://securetoken.google.com/my-project" {
		t.Errorf("GIPIssuerURL() = %q", url)
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
