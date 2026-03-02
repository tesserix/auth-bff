package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tesserix/auth-bff/internal/session"
)

// mockStore implements session.Store for testing.
type mockStore struct {
	pingErr error
	sessions map[string]*session.Session
}

func newMockStore() *mockStore {
	return &mockStore{sessions: make(map[string]*session.Session)}
}

func (m *mockStore) Ping(ctx context.Context) error { return m.pingErr }
func (m *mockStore) CreateSession(ctx context.Context, s *session.Session) error {
	m.sessions[s.ID] = s
	return nil
}
func (m *mockStore) GetSession(ctx context.Context, id string) (*session.Session, error) {
	if s, ok := m.sessions[id]; ok {
		return s, nil
	}
	return nil, session.ErrNotFound
}
func (m *mockStore) UpdateSession(ctx context.Context, s *session.Session) error {
	m.sessions[s.ID] = s
	return nil
}
func (m *mockStore) DeleteSession(ctx context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}
func (m *mockStore) DeleteUserSessions(ctx context.Context, userID string) error { return nil }
func (m *mockStore) SaveAuthFlowState(ctx context.Context, s *session.AuthFlowState) error {
	return nil
}
func (m *mockStore) GetAuthFlowState(ctx context.Context, state string) (*session.AuthFlowState, error) {
	return nil, session.ErrNotFound
}
func (m *mockStore) SaveMFASession(ctx context.Context, s *session.MFASession) error { return nil }
func (m *mockStore) GetMFASession(ctx context.Context, id string) (*session.MFASession, error) {
	return nil, session.ErrNotFound
}
func (m *mockStore) UpdateMFASession(ctx context.Context, s *session.MFASession) error { return nil }
func (m *mockStore) DeleteMFASession(ctx context.Context, id string) error              { return nil }
func (m *mockStore) SaveTOTPSetup(ctx context.Context, key string, s *session.TOTPSetupSession) error {
	return nil
}
func (m *mockStore) GetTOTPSetup(ctx context.Context, key string) (*session.TOTPSetupSession, error) {
	return nil, session.ErrNotFound
}
func (m *mockStore) DeleteTOTPSetup(ctx context.Context, key string) error { return nil }
func (m *mockStore) SavePasskeyChallenge(ctx context.Context, id string, c *session.PasskeyChallenge) error {
	return nil
}
func (m *mockStore) GetPasskeyChallenge(ctx context.Context, id string) (*session.PasskeyChallenge, error) {
	return nil, session.ErrNotFound
}
func (m *mockStore) ConsumePasskeyChallenge(ctx context.Context, id string) (*session.PasskeyChallenge, error) {
	return nil, session.ErrNotFound
}
func (m *mockStore) SaveSessionTransfer(ctx context.Context, code string, t *session.SessionTransfer) error {
	return nil
}
func (m *mockStore) ConsumeSessionTransfer(ctx context.Context, code string) (*session.SessionTransfer, error) {
	return nil, session.ErrNotFound
}
func (m *mockStore) SaveWSTicket(ctx context.Context, ticket string, t *session.WSTicket) error {
	return nil
}
func (m *mockStore) ConsumeWSTicket(ctx context.Context, ticket string) (*session.WSTicket, error) {
	return nil, session.ErrNotFound
}
func (m *mockStore) SaveDeviceTrust(ctx context.Context, hash string, userID string) error {
	return nil
}
func (m *mockStore) GetDeviceTrust(ctx context.Context, hash string) (string, error) {
	return "", session.ErrNotFound
}
func (m *mockStore) DeleteDeviceTrust(ctx context.Context, hash string) error { return nil }
func (m *mockStore) CheckRateLimit(ctx context.Context, key string, max int, window time.Duration) (bool, int, error) {
	return true, max, nil
}

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func TestHealth(t *testing.T) {
	router := setupRouter()
	store := newMockStore()
	handler := NewHealthHandler(store)
	handler.RegisterRoutes(router)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.String() == "" {
		t.Error("expected non-empty body")
	}
}

func TestReady_Success(t *testing.T) {
	router := setupRouter()
	store := newMockStore()
	handler := NewHealthHandler(store)
	handler.RegisterRoutes(router)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestReady_RedisDown(t *testing.T) {
	router := setupRouter()
	store := newMockStore()
	store.pingErr = errors.New("connection refused")
	handler := NewHealthHandler(store)
	handler.RegisterRoutes(router)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}
