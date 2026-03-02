package session

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupTestStore(t *testing.T) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewRedisStore(client), mr
}

func TestSession_CRUD(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	sess := &Session{
		ID:           "sess-123",
		UserID:       "user-1",
		Email:        "test@example.com",
		TenantID:     "tenant-1",
		TenantSlug:   "demo",
		ClientType:   "internal",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		CSRFToken:    "csrf-token",
	}

	// Create
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Get
	got, err := store.GetSession(ctx, "sess-123")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", got.UserID)
	}
	if got.Email != "test@example.com" {
		t.Errorf("Email = %q, want test@example.com", got.Email)
	}
	if got.TenantSlug != "demo" {
		t.Errorf("TenantSlug = %q, want demo", got.TenantSlug)
	}
	if got.CreatedAt == 0 {
		t.Error("CreatedAt should be set")
	}
	if got.LastAccessedAt == 0 {
		t.Error("LastAccessedAt should be set")
	}

	// Update
	sess.Email = "updated@example.com"
	if err := store.UpdateSession(ctx, sess); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}
	got, _ = store.GetSession(ctx, "sess-123")
	if got.Email != "updated@example.com" {
		t.Errorf("updated Email = %q, want updated@example.com", got.Email)
	}

	// Delete
	if err := store.DeleteSession(ctx, "sess-123"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	_, err = store.GetSession(ctx, "sess-123")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestSession_NotFound(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	_, err := store.GetSession(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAuthFlowState_SingleUse(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	state := &AuthFlowState{
		State:        "state-abc",
		Nonce:        "nonce-123",
		CodeVerifier: "verifier-xyz",
		ClientType:   "internal",
		ReturnTo:     "/dashboard",
		AppName:      "admin",
	}

	if err := store.SaveAuthFlowState(ctx, state); err != nil {
		t.Fatalf("SaveAuthFlowState: %v", err)
	}

	// First retrieval succeeds
	got, err := store.GetAuthFlowState(ctx, "state-abc")
	if err != nil {
		t.Fatalf("GetAuthFlowState: %v", err)
	}
	if got.Nonce != "nonce-123" {
		t.Errorf("Nonce = %q, want nonce-123", got.Nonce)
	}
	if got.ReturnTo != "/dashboard" {
		t.Errorf("ReturnTo = %q, want /dashboard", got.ReturnTo)
	}

	// Second retrieval fails (single-use)
	_, err = store.GetAuthFlowState(ctx, "state-abc")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound on second retrieval, got %v", err)
	}
}

func TestMFASession_CRUD(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	mfa := &MFASession{
		ID:           "mfa-123",
		UserID:       "user-1",
		Email:        "test@example.com",
		TenantID:     "tenant-1",
		AccessToken:  "at",
		RefreshToken: "rt",
		AttemptCount: 0,
	}

	if err := store.SaveMFASession(ctx, mfa); err != nil {
		t.Fatalf("SaveMFASession: %v", err)
	}

	got, err := store.GetMFASession(ctx, "mfa-123")
	if err != nil {
		t.Fatalf("GetMFASession: %v", err)
	}
	if got.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", got.UserID)
	}

	// Update attempt count
	got.AttemptCount = 3
	if err := store.UpdateMFASession(ctx, got); err != nil {
		t.Fatalf("UpdateMFASession: %v", err)
	}
	got2, _ := store.GetMFASession(ctx, "mfa-123")
	if got2.AttemptCount != 3 {
		t.Errorf("AttemptCount = %d, want 3", got2.AttemptCount)
	}

	// Delete
	if err := store.DeleteMFASession(ctx, "mfa-123"); err != nil {
		t.Fatalf("DeleteMFASession: %v", err)
	}
	_, err = store.GetMFASession(ctx, "mfa-123")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestTOTPSetup_CRUD(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	setup := &TOTPSetupSession{
		UserID:           "user-1",
		EncryptedSecret:  "encrypted-secret-data",
		BackupCodeHashes: []string{"hash1", "hash2", "hash3"},
	}

	if err := store.SaveTOTPSetup(ctx, "setup-123", setup); err != nil {
		t.Fatalf("SaveTOTPSetup: %v", err)
	}

	got, err := store.GetTOTPSetup(ctx, "setup-123")
	if err != nil {
		t.Fatalf("GetTOTPSetup: %v", err)
	}
	if got.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", got.UserID)
	}
	if len(got.BackupCodeHashes) != 3 {
		t.Errorf("BackupCodeHashes len = %d, want 3", len(got.BackupCodeHashes))
	}

	if err := store.DeleteTOTPSetup(ctx, "setup-123"); err != nil {
		t.Fatalf("DeleteTOTPSetup: %v", err)
	}
	_, err = store.GetTOTPSetup(ctx, "setup-123")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestPasskeyChallenge_Consume(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	challenge := &PasskeyChallenge{
		Type:      "registration",
		Challenge: "challenge-data",
		UserID:    "user-1",
		RPID:      "tesserix.app",
	}

	if err := store.SavePasskeyChallenge(ctx, "pk-123", challenge); err != nil {
		t.Fatalf("SavePasskeyChallenge: %v", err)
	}

	// Consume (get + delete)
	got, err := store.ConsumePasskeyChallenge(ctx, "pk-123")
	if err != nil {
		t.Fatalf("ConsumePasskeyChallenge: %v", err)
	}
	if got.Type != "registration" {
		t.Errorf("Type = %q, want registration", got.Type)
	}

	// Second consume fails
	_, err = store.ConsumePasskeyChallenge(ctx, "pk-123")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound on second consume, got %v", err)
	}
}

func TestWSTicket_Consume(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	ticket := &WSTicket{
		UserID:     "user-1",
		TenantID:   "tenant-1",
		TenantSlug: "demo",
		SessionID:  "sess-1",
	}

	if err := store.SaveWSTicket(ctx, "ticket-abc", ticket); err != nil {
		t.Fatalf("SaveWSTicket: %v", err)
	}

	got, err := store.ConsumeWSTicket(ctx, "ticket-abc")
	if err != nil {
		t.Fatalf("ConsumeWSTicket: %v", err)
	}
	if got.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", got.UserID)
	}

	// Consumed
	_, err = store.ConsumeWSTicket(ctx, "ticket-abc")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSessionTransfer_Consume(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	transfer := &SessionTransfer{
		SessionID:  "sess-1",
		UserID:     "user-1",
		TenantID:   "tenant-1",
		SourceApp:  "admin",
		TargetApp:  "home",
	}

	if err := store.SaveSessionTransfer(ctx, "code-xyz", transfer); err != nil {
		t.Fatalf("SaveSessionTransfer: %v", err)
	}

	got, err := store.ConsumeSessionTransfer(ctx, "code-xyz")
	if err != nil {
		t.Fatalf("ConsumeSessionTransfer: %v", err)
	}
	if got.SourceApp != "admin" || got.TargetApp != "home" {
		t.Errorf("SourceApp=%q TargetApp=%q", got.SourceApp, got.TargetApp)
	}

	_, err = store.ConsumeSessionTransfer(ctx, "code-xyz")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDeviceTrust(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	if err := store.SaveDeviceTrust(ctx, "device-hash-1", "user-1"); err != nil {
		t.Fatalf("SaveDeviceTrust: %v", err)
	}

	got, err := store.GetDeviceTrust(ctx, "device-hash-1")
	if err != nil {
		t.Fatalf("GetDeviceTrust: %v", err)
	}
	if got != "user-1" {
		t.Errorf("got %q, want user-1", got)
	}

	if err := store.DeleteDeviceTrust(ctx, "device-hash-1"); err != nil {
		t.Fatalf("DeleteDeviceTrust: %v", err)
	}

	_, err = store.GetDeviceTrust(ctx, "device-hash-1")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCheckRateLimit(t *testing.T) {
	store, _ := setupTestStore(t)
	ctx := context.Background()

	// First 3 requests allowed
	for i := 0; i < 3; i++ {
		allowed, remaining, err := store.CheckRateLimit(ctx, "test-key", 3, time.Minute)
		if err != nil {
			t.Fatalf("CheckRateLimit: %v", err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
		if remaining != 3-i-1 {
			t.Errorf("remaining = %d, want %d", remaining, 3-i-1)
		}
	}

	// 4th request denied
	allowed, _, err := store.CheckRateLimit(ctx, "test-key", 3, time.Minute)
	if err != nil {
		t.Fatalf("CheckRateLimit: %v", err)
	}
	if allowed {
		t.Error("4th request should be denied")
	}
}

func TestPing(t *testing.T) {
	store, _ := setupTestStore(t)
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}
