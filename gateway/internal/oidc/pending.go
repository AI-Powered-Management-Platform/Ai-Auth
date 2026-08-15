package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// PendingTTL bounds how long a half-finished login may sit waiting for the
// user. Long enough for a passkey prompt and a fumbled retry; short enough
// that an abandoned tab is not a durable handle.
const PendingTTL = 10 * time.Minute

// PendingStore holds validated authorization requests between /authorize and
// the completion of the login ceremony. The browser carries only an opaque
// id: the request's parameters never make a round trip through the client,
// so nothing the user's browser holds can alter what was requested.
type PendingStore struct {
	mu       sync.Mutex
	requests map[string]pendingEntry
	now      func() time.Time
}

type pendingEntry struct {
	req       AuthzRequest
	expiresAt time.Time
}

func NewPendingStore() *PendingStore {
	return &PendingStore{requests: make(map[string]pendingEntry), now: time.Now}
}

func (s *PendingStore) Put(req AuthzRequest) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, e := range s.requests {
		if now.After(e.expiresAt) {
			delete(s.requests, k)
		}
	}
	s.requests[id] = pendingEntry{req: req, expiresAt: now.Add(PendingTTL)}
	return id, nil
}

// Take consumes a pending request. Single use: a login ceremony completes
// once, and a replayed id must not resurrect an old authorization.
func (s *PendingStore) Take(id string) (*AuthzRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.requests[id]
	if !ok {
		return nil, false
	}
	delete(s.requests, id)
	if s.now().After(e.expiresAt) {
		return nil, false
	}
	return &e.req, true
}

func (s *PendingStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}
