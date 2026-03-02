package events

import (
	"context"
	"time"

	"github.com/tesserix/go-shared/events"
	"github.com/tesserix/go-shared/logger"
)

// Publisher wraps go-shared NATS event publishing for auth events.
type Publisher struct {
	pub    *events.Publisher
	logger *logger.Logger
}

// NewPublisher creates a new auth event publisher.
// Returns nil (with a warning) if NATS is unavailable — events are optional.
func NewPublisher(natsURL string, logger *logger.Logger) *Publisher {
	if natsURL == "" {
		logger.Warn("NATS URL not configured, event publishing disabled")
		return &Publisher{logger: logger}
	}

	cfg := events.DefaultPublisherConfig(natsURL)
	cfg.Name = "auth-bff"
	cfg.ConnectTimeout = 10 * time.Second

	pub, err := events.NewPublisher(cfg, nil) // go-shared uses logrus; we pass nil
	if err != nil {
		logger.Warn("NATS connection failed, event publishing disabled", "error", err)
		return &Publisher{logger: logger}
	}

	// Ensure auth event stream exists
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pub.EnsureStream(ctx, "AUTH_EVENTS", []string{"auth.>"}); err != nil {
		logger.Warn("failed to ensure auth event stream", "error", err)
	}

	return &Publisher{pub: pub, logger: logger}
}

// PublishLoginSuccess publishes a login success event (non-blocking).
func (p *Publisher) PublishLoginSuccess(ctx context.Context, tenantID, userID, email, ipAddress, userAgent, loginMethod string) {
	if p.pub == nil {
		return
	}

	go func() {
		event := &events.AuthEvent{
			BaseEvent: events.BaseEvent{
				EventType: "auth.login_success",
				TenantID:  tenantID,
				Timestamp: time.Now(),
			},
			UserID:      userID,
			Email:       email,
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			LoginMethod: loginMethod,
		}

		if err := p.pub.Publish(ctx, event); err != nil {
			p.logger.Warn("failed to publish login event", "error", err)
		}
	}()
}

// PublishLoginFailed publishes a login failure event (non-blocking).
func (p *Publisher) PublishLoginFailed(ctx context.Context, tenantID, email, ipAddress, userAgent, reason string) {
	if p.pub == nil {
		return
	}

	go func() {
		event := &events.AuthEvent{
			BaseEvent: events.BaseEvent{
				EventType: "auth.login_failed",
				TenantID:  tenantID,
				Timestamp: time.Now(),
			},
			Email:     email,
			IPAddress: ipAddress,
			UserAgent: userAgent,
		}

		if err := p.pub.Publish(ctx, event); err != nil {
			p.logger.Warn("failed to publish login failed event", "error", err)
		}
	}()
}

// PublishLogout publishes a logout event (non-blocking).
func (p *Publisher) PublishLogout(ctx context.Context, tenantID, userID, email string) {
	if p.pub == nil {
		return
	}

	go func() {
		event := &events.AuthEvent{
			BaseEvent: events.BaseEvent{
				EventType: "auth.logout",
				TenantID:  tenantID,
				Timestamp: time.Now(),
			},
			UserID: userID,
			Email:  email,
		}

		if err := p.pub.Publish(ctx, event); err != nil {
			p.logger.Warn("failed to publish logout event", "error", err)
		}
	}()
}

// Close shuts down the NATS connection.
func (p *Publisher) Close() {
	if p.pub != nil {
		p.pub.Close()
	}
}
