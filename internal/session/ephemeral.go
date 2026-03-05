package session

import (
	"sync"
	"time"
)

// EphemeralStore is an in-memory TTL store for short-lived auth state
// (PKCE flows, MFA challenges, passkey challenges).
// Data is lost on instance restart, which is acceptable for Cloud Run —
// users simply retry the auth flow.
type EphemeralStore struct {
	mu      sync.RWMutex
	entries map[string]*ephemeralEntry
}

type ephemeralEntry struct {
	data      []byte
	expiresAt time.Time
}

// NewEphemeralStore creates a new in-memory TTL store with background cleanup.
func NewEphemeralStore() *EphemeralStore {
	s := &EphemeralStore{
		entries: make(map[string]*ephemeralEntry),
	}
	go s.cleanup()
	return s
}

// Set stores data with a TTL.
func (s *EphemeralStore) Set(key string, data []byte, ttl time.Duration) {
	s.mu.Lock()
	s.entries[key] = &ephemeralEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
	s.mu.Unlock()
}

// Get retrieves data if it exists and hasn't expired.
func (s *EphemeralStore) Get(key string) ([]byte, bool) {
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.data, true
}

// Consume retrieves and deletes data (single-use).
func (s *EphemeralStore) Consume(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		delete(s.entries, key)
		return nil, false
	}
	delete(s.entries, key)
	return entry.data, true
}

// Delete removes an entry.
func (s *EphemeralStore) Delete(key string) {
	s.mu.Lock()
	delete(s.entries, key)
	s.mu.Unlock()
}

func (s *EphemeralStore) cleanup() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for key, entry := range s.entries {
			if now.After(entry.expiresAt) {
				delete(s.entries, key)
			}
		}
		s.mu.Unlock()
	}
}
