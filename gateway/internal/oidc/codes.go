package oidc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	ErrCodeUnknown  = errors.New("authorization code is unknown, expired, or already used")
	ErrCodeClient   = errors.New("authorization code was not issued to this client")
	ErrCodeRedirect = errors.New("redirect_uri does not match the one used at authorization")
)

// CodeTTL is short by design. An authorization code is a one-time bearer
// value in transit; the window in which a leaked one is useful should be
// measured in seconds, not minutes.
const CodeTTL = 60 * time.Second

// Grant is what an authorization code stands for. It is never sent to a
// client — the code is the handle, this is what the server remembers.
type Grant struct {
	ClientID      string
	RedirectURI   string
	Scope         string
	Nonce         string
	CodeChallenge string
	SubjectID     string
	TenantID      string
	// AuthTime feeds max_age and step-up decisions later.
	AuthTime time.Time

	expiresAt time.Time
}

// CodeStore issues and redeems authorization codes exactly once.
//
// In-memory for v1, which means codes do not survive a restart and do not
// span replicas. That is a deployment limitation, not a security one — the
// failure mode is a login that must be retried, never a code that works
// twice. Postgres-backed storage replaces this before multi-replica.
type CodeStore struct {
	mu    sync.Mutex
	codes map[string]Grant
	now   func() time.Time
}

func NewCodeStore() *CodeStore {
	return &CodeStore{codes: make(map[string]Grant), now: time.Now}
}

// Issue mints a code for a grant. The code is 256 bits from crypto/rand:
// guessing is not a threat model we want to reason about.
func (s *CodeStore) Issue(g Grant) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// A failing CSPRNG must never degrade to a weaker source.
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	g.expiresAt = s.now().Add(CodeTTL)
	s.codes[code] = g
	return code, nil
}

// Redeem consumes a code. It is removed before any validation, so a wrong
// client or redirect burns the code rather than allowing a retry — an
// attacker who has stolen a code gets one attempt, not an oracle to probe.
func (s *CodeStore) Redeem(code, clientID, redirectURI string) (*Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	g, ok := s.codes[code]
	if !ok {
		return nil, ErrCodeUnknown
	}
	delete(s.codes, code)

	if s.now().After(g.expiresAt) {
		return nil, ErrCodeUnknown
	}
	// Constant-time: these are secrets in the sense that a timing signal
	// would tell an attacker which half of a guess was right.
	if subtle.ConstantTimeCompare([]byte(g.ClientID), []byte(clientID)) != 1 {
		return nil, ErrCodeClient
	}
	if subtle.ConstantTimeCompare([]byte(g.RedirectURI), []byte(redirectURI)) != 1 {
		return nil, ErrCodeRedirect
	}
	return &g, nil
}

// evictExpiredLocked keeps the map from growing without bound. Callers hold
// the lock.
func (s *CodeStore) evictExpiredLocked() {
	now := s.now()
	for code, g := range s.codes {
		if now.After(g.expiresAt) {
			delete(s.codes, code)
		}
	}
}

// Len reports outstanding codes. Test and metrics use only.
func (s *CodeStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.codes)
}
