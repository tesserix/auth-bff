package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrNotFound = errors.New("session not found")
	ErrExpired  = errors.New("session expired")
)

// Store defines the interface for session persistence.
type Store interface {
	// Session CRUD
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	UpdateSession(ctx context.Context, s *Session) error
	DeleteSession(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID string) error

	// Auth flow state (single-use)
	SaveAuthFlowState(ctx context.Context, state *AuthFlowState) error
	GetAuthFlowState(ctx context.Context, stateParam string) (*AuthFlowState, error)

	// MFA session
	SaveMFASession(ctx context.Context, s *MFASession) error
	GetMFASession(ctx context.Context, id string) (*MFASession, error)
	UpdateMFASession(ctx context.Context, s *MFASession) error
	DeleteMFASession(ctx context.Context, id string) error

	// TOTP setup
	SaveTOTPSetup(ctx context.Context, key string, s *TOTPSetupSession) error
	GetTOTPSetup(ctx context.Context, key string) (*TOTPSetupSession, error)
	DeleteTOTPSetup(ctx context.Context, key string) error

	// Passkey challenges (single-use)
	SavePasskeyChallenge(ctx context.Context, id string, c *PasskeyChallenge) error
	GetPasskeyChallenge(ctx context.Context, id string) (*PasskeyChallenge, error)
	ConsumePasskeyChallenge(ctx context.Context, id string) (*PasskeyChallenge, error)

	// Session transfer
	SaveSessionTransfer(ctx context.Context, code string, t *SessionTransfer) error
	ConsumeSessionTransfer(ctx context.Context, code string) (*SessionTransfer, error)

	// WebSocket tickets
	SaveWSTicket(ctx context.Context, ticket string, t *WSTicket) error
	ConsumeWSTicket(ctx context.Context, ticket string) (*WSTicket, error)

	// Device trust
	SaveDeviceTrust(ctx context.Context, hash string, userID string) error
	GetDeviceTrust(ctx context.Context, hash string) (string, error)
	DeleteDeviceTrust(ctx context.Context, hash string) error

	// Rate limiting
	CheckRateLimit(ctx context.Context, key string, maxAttempts int, window time.Duration) (bool, int, error)

	// Health
	Ping(ctx context.Context) error
}

// RedisStore implements Store using Redis.
type RedisStore struct {
	client redis.UniversalClient
}

// NewRedisStore creates a new Redis-backed session store.
func NewRedisStore(client redis.UniversalClient) *RedisStore {
	return &RedisStore{client: client}
}

func (r *RedisStore) CreateSession(ctx context.Context, s *Session) error {
	now := time.Now().Unix()
	s.CreatedAt = now
	s.LastAccessedAt = now
	return r.setJSON(ctx, PrefixSession+s.ID, s, TTLSession)
}

func (r *RedisStore) GetSession(ctx context.Context, id string) (*Session, error) {
	var s Session
	if err := r.getJSON(ctx, PrefixSession+id, &s); err != nil {
		return nil, err
	}
	// Update last accessed time (fire and forget)
	s.LastAccessedAt = time.Now().Unix()
	_ = r.setJSON(ctx, PrefixSession+id, &s, TTLSession)
	return &s, nil
}

func (r *RedisStore) UpdateSession(ctx context.Context, s *Session) error {
	s.LastAccessedAt = time.Now().Unix()
	return r.setJSON(ctx, PrefixSession+s.ID, s, TTLSession)
}

func (r *RedisStore) DeleteSession(ctx context.Context, id string) error {
	return r.client.Del(ctx, PrefixSession+id).Err()
}

func (r *RedisStore) DeleteUserSessions(ctx context.Context, userID string) error {
	// Scan for user sessions — in production this would use a user→sessions index.
	// For now, this is a best-effort scan.
	iter := r.client.Scan(ctx, 0, PrefixSession+"*", 100).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		var s Session
		if err := r.getJSON(ctx, key, &s); err == nil && s.UserID == userID {
			_ = r.client.Del(ctx, key).Err()
		}
	}
	return iter.Err()
}

func (r *RedisStore) SaveAuthFlowState(ctx context.Context, state *AuthFlowState) error {
	state.CreatedAt = time.Now().Unix()
	return r.setJSON(ctx, PrefixAuthFlow+state.State, state, TTLAuthFlow)
}

func (r *RedisStore) GetAuthFlowState(ctx context.Context, stateParam string) (*AuthFlowState, error) {
	var s AuthFlowState
	if err := r.getJSON(ctx, PrefixAuthFlow+stateParam, &s); err != nil {
		return nil, err
	}
	// Single-use: delete after retrieval
	_ = r.client.Del(ctx, PrefixAuthFlow+stateParam).Err()
	return &s, nil
}

func (r *RedisStore) SaveMFASession(ctx context.Context, s *MFASession) error {
	return r.setJSON(ctx, PrefixMFASession+s.ID, s, TTLMFASession)
}

func (r *RedisStore) GetMFASession(ctx context.Context, id string) (*MFASession, error) {
	var s MFASession
	if err := r.getJSON(ctx, PrefixMFASession+id, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *RedisStore) UpdateMFASession(ctx context.Context, s *MFASession) error {
	return r.setJSON(ctx, PrefixMFASession+s.ID, s, TTLMFASession)
}

func (r *RedisStore) DeleteMFASession(ctx context.Context, id string) error {
	return r.client.Del(ctx, PrefixMFASession+id).Err()
}

func (r *RedisStore) SaveTOTPSetup(ctx context.Context, key string, s *TOTPSetupSession) error {
	return r.setJSON(ctx, PrefixTOTPSetup+key, s, TTLTOTPSetup)
}

func (r *RedisStore) GetTOTPSetup(ctx context.Context, key string) (*TOTPSetupSession, error) {
	var s TOTPSetupSession
	if err := r.getJSON(ctx, PrefixTOTPSetup+key, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *RedisStore) DeleteTOTPSetup(ctx context.Context, key string) error {
	return r.client.Del(ctx, PrefixTOTPSetup+key).Err()
}

func (r *RedisStore) SavePasskeyChallenge(ctx context.Context, id string, c *PasskeyChallenge) error {
	return r.setJSON(ctx, PrefixPasskeyChallenge+id, c, TTLPasskeyChallenge)
}

func (r *RedisStore) GetPasskeyChallenge(ctx context.Context, id string) (*PasskeyChallenge, error) {
	var c PasskeyChallenge
	if err := r.getJSON(ctx, PrefixPasskeyChallenge+id, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *RedisStore) ConsumePasskeyChallenge(ctx context.Context, id string) (*PasskeyChallenge, error) {
	c, err := r.GetPasskeyChallenge(ctx, id)
	if err != nil {
		return nil, err
	}
	_ = r.client.Del(ctx, PrefixPasskeyChallenge+id).Err()
	return c, nil
}

func (r *RedisStore) SaveSessionTransfer(ctx context.Context, code string, t *SessionTransfer) error {
	return r.setJSON(ctx, PrefixSessionTransfer+code, t, TTLSessionTransfer)
}

func (r *RedisStore) ConsumeSessionTransfer(ctx context.Context, code string) (*SessionTransfer, error) {
	var t SessionTransfer
	if err := r.getJSON(ctx, PrefixSessionTransfer+code, &t); err != nil {
		return nil, err
	}
	_ = r.client.Del(ctx, PrefixSessionTransfer+code).Err()
	return &t, nil
}

func (r *RedisStore) SaveWSTicket(ctx context.Context, ticket string, t *WSTicket) error {
	return r.setJSON(ctx, PrefixWSTicket+ticket, t, TTLWSTicket)
}

func (r *RedisStore) ConsumeWSTicket(ctx context.Context, ticket string) (*WSTicket, error) {
	var t WSTicket
	if err := r.getJSON(ctx, PrefixWSTicket+ticket, &t); err != nil {
		return nil, err
	}
	_ = r.client.Del(ctx, PrefixWSTicket+ticket).Err()
	return &t, nil
}

func (r *RedisStore) SaveDeviceTrust(ctx context.Context, hash string, userID string) error {
	return r.client.Set(ctx, PrefixDeviceTrust+hash, userID, TTLDeviceTrust).Err()
}

func (r *RedisStore) GetDeviceTrust(ctx context.Context, hash string) (string, error) {
	val, err := r.client.Get(ctx, PrefixDeviceTrust+hash).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	return val, err
}

func (r *RedisStore) DeleteDeviceTrust(ctx context.Context, hash string) error {
	return r.client.Del(ctx, PrefixDeviceTrust+hash).Err()
}

func (r *RedisStore) CheckRateLimit(ctx context.Context, key string, maxAttempts int, window time.Duration) (bool, int, error) {
	fullKey := PrefixRateLimit + key
	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, fullKey)
	pipe.Expire(ctx, fullKey, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return true, 0, err // fail open
	}
	count := int(incrCmd.Val())
	return count <= maxAttempts, maxAttempts - count, nil
}

func (r *RedisStore) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// helpers

func (r *RedisStore) setJSON(ctx context.Context, key string, v interface{}, ttl time.Duration) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return r.client.Set(ctx, key, data, ttl).Err()
}

func (r *RedisStore) getJSON(ctx context.Context, key string, v interface{}) error {
	data, err := r.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
