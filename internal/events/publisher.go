package events

import (
	"context"
	"log/slog"

	"github.com/tesserix/go-shared/messaging"
)

// Publisher wraps go-shared Pub/Sub event publishing for auth events.
type Publisher struct {
	pub *messaging.Publisher
}

// NewPublisher creates a new auth event publisher using Google Pub/Sub.
// Returns a no-op publisher if projectID is empty (local dev without Pub/Sub).
func NewPublisher(ctx context.Context, projectID string) *Publisher {
	if projectID == "" {
		slog.Warn("GCP project ID not configured, event publishing disabled")
		return &Publisher{}
	}

	pub, err := messaging.NewPublisher(ctx, projectID, "auth-bff")
	if err != nil {
		slog.Warn("Pub/Sub publisher creation failed, event publishing disabled", "error", err)
		return &Publisher{}
	}

	return &Publisher{pub: pub}
}

// PublishLoginSuccess publishes a login success event (async, fire-and-forget).
func (p *Publisher) PublishLoginSuccess(ctx context.Context, tenantID, userID, email, ipAddress, userAgent, loginMethod string) {
	if p.pub == nil {
		return
	}

	p.pub.PublishAsync(ctx, messaging.TopicAuditEvents, messaging.EventUserLogin, tenantID, map[string]string{
		"user_id":      userID,
		"email":        email,
		"ip_address":   ipAddress,
		"user_agent":   userAgent,
		"login_method": loginMethod,
	})
}

// PublishLoginFailed publishes a login failure event (async, fire-and-forget).
func (p *Publisher) PublishLoginFailed(ctx context.Context, tenantID, email, ipAddress, userAgent, reason string) {
	if p.pub == nil {
		return
	}

	p.pub.PublishAsync(ctx, messaging.TopicAuditEvents, "auth.login.failed", tenantID, map[string]string{
		"email":      email,
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"reason":     reason,
	})
}

// PublishLogout publishes a logout event (async, fire-and-forget).
func (p *Publisher) PublishLogout(ctx context.Context, tenantID, userID, email string) {
	if p.pub == nil {
		return
	}

	p.pub.PublishAsync(ctx, messaging.TopicAuditEvents, messaging.EventUserLogout, tenantID, map[string]string{
		"user_id": userID,
		"email":   email,
	})
}

// PublishSessionCreated publishes a session creation event.
func (p *Publisher) PublishSessionCreated(ctx context.Context, tenantID, userID, sessionID string) {
	if p.pub == nil {
		return
	}

	p.pub.PublishAsync(ctx, messaging.TopicAuditEvents, messaging.EventSessionCreated, tenantID, map[string]string{
		"user_id":    userID,
		"session_id": sessionID,
	})
}

// Close flushes pending messages and releases resources.
func (p *Publisher) Close() error {
	if p.pub != nil {
		return p.pub.Close()
	}
	return nil
}
