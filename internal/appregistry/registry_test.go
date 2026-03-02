package appregistry

import (
	"testing"

	"github.com/tesserix/auth-bff/internal/config"
)

func testApps() []config.AppConfig {
	return []config.AppConfig{
		{
			Name:          "admin",
			Hosts:         []string{"*-admin.tesserix.app", "admin.localhost", "localhost:3000"},
			SessionCookie: "bff_session",
			AuthContext:   "staff",
		},
		{
			Name:          "home",
			Hosts:         []string{"tesserix.app", "www.tesserix.app", "company.tesserix.app", "localhost:3002"},
			SessionCookie: "bff_home_session",
			AuthContext:   "staff",
		},
		{
			Name:          "onboarding",
			Hosts:         []string{"onboarding.tesserix.app", "*-onboarding.tesserix.app", "localhost:3001"},
			SessionCookie: "bff_session",
			AuthContext:   "staff",
		},
		{
			Name:          "storefront",
			Hosts:         []string{"*.tesserix.app"},
			SessionCookie: "bff_storefront_session",
			AuthContext:   "customer",
		},
	}
}

func TestResolve(t *testing.T) {
	registry := New(testApps())

	tests := []struct {
		name     string
		host     string
		wantApp  string
		wantNil  bool
	}{
		// Admin hosts
		{"admin subdomain", "demo-admin.tesserix.app", "admin", false},
		{"another admin", "test-admin.tesserix.app", "admin", false},
		{"admin localhost", "localhost:3000", "admin", false},

		// Home hosts
		{"home root", "tesserix.app", "home", false},
		{"home www", "www.tesserix.app", "home", false},
		{"home company", "company.tesserix.app", "home", false},
		{"home localhost", "localhost:3002", "home", false},

		// Onboarding hosts
		{"onboarding", "onboarding.tesserix.app", "onboarding", false},
		{"onboarding prefixed", "demo-onboarding.tesserix.app", "onboarding", false},
		{"onboarding localhost", "localhost:3001", "onboarding", false},

		// Storefront (catch-all)
		{"storefront subdomain", "demo.tesserix.app", "storefront", false},
		{"storefront other", "myshop.tesserix.app", "storefront", false},

		// Case insensitive
		{"case insensitive", "Demo-Admin.Tesserix.App", "admin", false},

		// Comma-separated x-forwarded-host
		{"comma separated", "demo-admin.tesserix.app, 10.0.0.1", "admin", false},

		// Empty host
		{"empty host", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := registry.Resolve(tt.host)
			if tt.wantNil {
				if app != nil {
					t.Errorf("expected nil, got app %q", app.Name)
				}
				return
			}
			if app == nil {
				t.Fatalf("expected app %q, got nil", tt.wantApp)
			}
			if app.Name != tt.wantApp {
				t.Errorf("got app %q, want %q", app.Name, tt.wantApp)
			}
		})
	}
}

func TestResolveByName(t *testing.T) {
	registry := New(testApps())

	tests := []struct {
		name    string
		appName string
		wantNil bool
	}{
		{"admin", "admin", false},
		{"storefront", "storefront", false},
		{"home", "home", false},
		{"onboarding", "onboarding", false},
		{"unknown", "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := registry.ResolveByName(tt.appName)
			if tt.wantNil && app != nil {
				t.Errorf("expected nil, got %q", app.Name)
			}
			if !tt.wantNil && app == nil {
				t.Errorf("expected %q, got nil", tt.appName)
			}
		})
	}
}

func TestAllApps(t *testing.T) {
	apps := testApps()
	registry := New(apps)

	all := registry.AllApps()
	if len(all) != len(apps) {
		t.Errorf("got %d apps, want %d", len(all), len(apps))
	}

	// Verify it's a copy (modifying shouldn't affect registry)
	all[0].Name = "modified"
	orig := registry.ResolveByName("admin")
	if orig == nil {
		t.Fatal("admin app should still exist")
	}
	if orig.Name != "admin" {
		t.Errorf("original name modified: got %q", orig.Name)
	}
}

func TestMatchHost(t *testing.T) {
	tests := []struct {
		host    string
		pattern string
		want    bool
	}{
		{"demo-admin.tesserix.app", "*-admin.tesserix.app", true},
		{"tesserix.app", "*-admin.tesserix.app", false},
		{"-admin.tesserix.app", "*-admin.tesserix.app", false}, // must have prefix before *
		{"demo.tesserix.app", "*.tesserix.app", true},
		{"tesserix.app", "tesserix.app", true},
		{"other.com", "tesserix.app", false},
		{"localhost:3000", "localhost:3000", true},
		{"localhost:3001", "localhost:3000", false},
	}

	for _, tt := range tests {
		t.Run(tt.host+"→"+tt.pattern, func(t *testing.T) {
			if got := matchHost(tt.host, tt.pattern); got != tt.want {
				t.Errorf("matchHost(%q, %q) = %v, want %v", tt.host, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestExtractFirstHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"demo.tesserix.app", "demo.tesserix.app"},
		{"demo.tesserix.app, 10.0.0.1", "demo.tesserix.app"},
		{"demo.tesserix.app , proxy.internal", "demo.tesserix.app"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := extractFirstHost(tt.input); got != tt.want {
				t.Errorf("extractFirstHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolve_Priority(t *testing.T) {
	// Home hosts should take priority over storefront wildcard
	registry := New(testApps())

	// "tesserix.app" matches home (exact) and storefront (*.)
	app := registry.Resolve("tesserix.app")
	if app == nil || app.Name != "home" {
		name := ""
		if app != nil {
			name = app.Name
		}
		t.Errorf("expected home, got %q", name)
	}

	// "onboarding.tesserix.app" matches onboarding (exact) and storefront (*.)
	app = registry.Resolve("onboarding.tesserix.app")
	if app == nil || app.Name != "onboarding" {
		name := ""
		if app != nil {
			name = app.Name
		}
		t.Errorf("expected onboarding, got %q", name)
	}
}
