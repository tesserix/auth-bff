package events

import (
	"context"
	"testing"
)

func TestPublisher_NilSafe(t *testing.T) {
	// NewPublisher with empty project ID returns a no-op publisher
	pub := NewPublisher(context.Background(), "")

	// All methods should be nil-safe (no panic)
	ctx := context.Background()
	pub.PublishLoginSuccess(ctx, "t1", "u1", "a@b.com", "1.2.3.4", "Mozilla", "oidc")
	pub.PublishLoginFailed(ctx, "t1", "a@b.com", "1.2.3.4", "Mozilla", "bad password")
	pub.PublishLogout(ctx, "t1", "u1", "a@b.com")
	pub.PublishSessionCreated(ctx, "t1", "u1", "sess-123")

	if err := pub.Close(); err != nil {
		t.Errorf("Close() on nil publisher should not error: %v", err)
	}
}
