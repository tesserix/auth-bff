package gip

import (
	"context"
	"errors"
	"testing"

	"github.com/tesserix/auth-bff/internal/config"
)

// newTestApp creates a minimal AppConfig for use in gip tests.
func newTestApp(gipTenantID string) *config.AppConfig {
	return &config.AppConfig{
		Name:        "test-app",
		GIPTenantID: gipTenantID,
	}
}

// TestMockTokenVerifier_VerifyIDToken verifies the mock correctly records calls.
func TestMockTokenVerifier_VerifyIDToken(t *testing.T) {
	want := &IDTokenClaims{
		Subject:  "uid-123",
		Email:    "user@example.com",
		TenantID: "MP-Internal-uidfu",
	}
	mock := &MockTokenVerifier{VerifyResult: want}
	app := newTestApp("MP-Internal-uidfu")

	got, err := mock.VerifyIDToken(context.Background(), app, "fake-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Subject != want.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, want.Subject)
	}
	if mock.VerifyCalled != 1 {
		t.Errorf("VerifyCalled = %d, want 1", mock.VerifyCalled)
	}
	if mock.LastTenantID != "MP-Internal-uidfu" {
		t.Errorf("LastTenantID = %q, want MP-Internal-uidfu", mock.LastTenantID)
	}
}

// TestMockTokenVerifier_CrossTenantRejection verifies the mock returns errors correctly.
// This is the test stub for AUTH-04: mp-customer token rejected at mp-internal endpoint.
// TODO(AUTH-04): Replace mock with real Firebase TenantClient in Plan 02.
func TestMockTokenVerifier_CrossTenantRejection(t *testing.T) {
	crossTenantErr := errors.New("gip: token issued for tenant MP-Customer-cgob2, but app expects MP-Internal-uidfu")
	mock := &MockTokenVerifier{VerifyErr: crossTenantErr}
	app := newTestApp("MP-Internal-uidfu") // mp-internal app

	_, err := mock.VerifyIDToken(context.Background(), app, "mp-customer-token")
	if err == nil {
		t.Error("expected cross-tenant token to be rejected, got nil error")
	}
	if mock.LastTenantID != "MP-Internal-uidfu" {
		t.Errorf("LastTenantID = %q, want MP-Internal-uidfu", mock.LastTenantID)
	}
}

// TestMockTokenVerifier_RevokeTokens verifies mock records revocation calls.
func TestMockTokenVerifier_RevokeTokens(t *testing.T) {
	mock := &MockTokenVerifier{}
	app := newTestApp("MP-Internal-uidfu")

	err := mock.RevokeTokens(context.Background(), app, "uid-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.RevokeCalled != 1 {
		t.Errorf("RevokeCalled = %d, want 1", mock.RevokeCalled)
	}
}
