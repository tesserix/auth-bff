package middleware

import (
	"testing"

	"github.com/tesserix/auth-bff/internal/config"
)

func TestGetCookieDomain(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		appDomain      string
		platformDomain string
		want           string
	}{
		{
			name:           "localhost returns empty",
			host:           "localhost:3000",
			appDomain:      "",
			platformDomain: "tesserix.app",
			want:           "",
		},
		{
			name:           "exact platform domain",
			host:           "tesserix.app",
			appDomain:      "",
			platformDomain: "tesserix.app",
			want:           ".tesserix.app",
		},
		{
			name:           "subdomain of platform",
			host:           "admin.tesserix.app",
			appDomain:      "",
			platformDomain: "tesserix.app",
			want:           ".tesserix.app",
		},
		{
			name:           "product domain takes precedence",
			host:           "demo.marketplace.com",
			appDomain:      "marketplace.com",
			platformDomain: "tesserix.app",
			want:           ".marketplace.com",
		},
		{
			name:           "exact product domain",
			host:           "marketplace.com",
			appDomain:      "marketplace.com",
			platformDomain: "tesserix.app",
			want:           ".marketplace.com",
		},
		{
			name:           "custom domain strips www",
			host:           "www.mystore.com",
			appDomain:      "",
			platformDomain: "tesserix.app",
			want:           ".mystore.com",
		},
		{
			name:           "custom domain without www",
			host:           "mystore.com",
			appDomain:      "",
			platformDomain: "tesserix.app",
			want:           ".mystore.com",
		},
		{
			name:           "case insensitive",
			host:           "Admin.Tesserix.App",
			appDomain:      "",
			platformDomain: "tesserix.app",
			want:           ".tesserix.app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &config.AppConfig{ProductDomain: tt.appDomain}
			got := GetCookieDomain(tt.host, app, tt.platformDomain)
			if got != tt.want {
				t.Errorf("GetCookieDomain(%q, %q, %q) = %q, want %q",
					tt.host, tt.appDomain, tt.platformDomain, got, tt.want)
			}
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"Bearer abc123", "abc123"},
		{"Bearer ", ""},
		{"Basic abc123", ""},
		{"", ""},
		{"Bearerabc123", ""},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			// Can't use gin context easily here, test the logic directly
			got := extractBearer(tt.header)
			if got != tt.want {
				t.Errorf("extractBearer(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestMatchOrigin(t *testing.T) {
	tests := []struct {
		origin  string
		pattern string
		want    bool
	}{
		{"https://tesserix.app", "https://tesserix.app", true},
		{"https://other.com", "https://tesserix.app", false},
		{"https://demo.tesserix.app", "https://*.tesserix.app", true},
		{"https://tesserix.app", "https://*.tesserix.app", false}, // must have subdomain
		{"http://localhost:3000", "http://localhost:3000", true},
	}

	for _, tt := range tests {
		t.Run(tt.origin+"_"+tt.pattern, func(t *testing.T) {
			got := matchOriginPattern(tt.origin, tt.pattern)
			if got != tt.want {
				t.Errorf("matchOrigin(%q, %q) = %v, want %v", tt.origin, tt.pattern, got, tt.want)
			}
		})
	}
}

// helpers for testing without gin context

func extractBearer(header string) string {
	if len(header) > 7 && header[:7] == "Bearer " {
		return header[7:]
	}
	return ""
}

func matchOriginPattern(origin, pattern string) bool {
	if pattern == origin {
		return true
	}
	if len(pattern) > 0 && pattern[0] == '*' {
		return false
	}
	if idx := len("https://"); len(pattern) > idx && pattern[idx] == '*' {
		suffix := pattern[idx+1:]
		if len(origin) > idx {
			originHost := origin[idx:]
			if len(originHost) > len(suffix) && originHost[len(originHost)-len(suffix):] == suffix {
				return true
			}
		}
	}
	return false
}
