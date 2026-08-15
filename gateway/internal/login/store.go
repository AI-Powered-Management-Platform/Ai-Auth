// Package login runs the passkey ceremony: issue a challenge, verify the
// assertion through the Guard, and hand back an authorization code.
package login

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ChallengeTTL bounds how long a challenge stays usable. A challenge is the
// freshness proof in the whole ceremony; a long-lived one is a replay window.
const ChallengeTTL = 2 * time.Minute

var (
	ErrNoChallenge  = errors.New("no active challenge for this request")
	ErrNoCredential = errors.New("credential not found")
)

// Credential is a registered passkey. PublicKey is an uncompressed SEC1
// P-256 point; COSE unwrapping happens at registration so the login path
// stays small.
type Credential struct {
	ID        string
	TenantID  string
	SubjectID string
	PublicKey []byte
	SignCount uint32
}

// Challenges holds the random value issued at the start of a ceremony,
// keyed by the pending authorization id. Single use: a challenge that can be
// answered twice is not a freshness proof.
type Challenges struct {
	mu    sync.Mutex
	items map[string]challenge
	now   func() time.Time
}

type challenge struct {
	value     []byte
	expiresAt time.Time
}

func NewChallenges() *Challenges {
	return &Challenges{items: make(map[string]challenge), now: time.Now}
}

func (c *Challenges) Issue(rid string) ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, v := range c.items {
		if now.After(v.expiresAt) {
			delete(c.items, k)
		}
	}
	// Re-issuing for the same rid replaces the previous challenge, so a
	// restarted ceremony cannot leave an older one answerable.
	c.items[rid] = challenge{value: raw, expiresAt: now.Add(ChallengeTTL)}
	return raw, nil
}

// Take consumes the challenge for a request. Consumed whether or not the
// assertion later verifies: one challenge, one attempt.
func (c *Challenges) Take(rid string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.items[rid]
	if !ok {
		return nil, ErrNoChallenge
	}
	delete(c.items, rid)
	if c.now().After(ch.expiresAt) {
		return nil, ErrNoChallenge
	}
	return ch.value, nil
}

func (c *Challenges) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// Credentials is the registered-passkey lookup. In-memory for v1; the
// Postgres implementation stores public keys in the clear (they are public)
// and the subject binding behind blind indexing.
type Credentials struct {
	mu    sync.RWMutex
	items map[string]Credential
}

func NewCredentials() *Credentials {
	return &Credentials{items: make(map[string]Credential)}
}

func (s *Credentials) Add(c Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[c.ID] = c
}

func (s *Credentials) Get(id string) (Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.items[id]
	if !ok {
		return Credential{}, ErrNoCredential
	}
	return c, nil
}

// UpdateSignCount persists the counter the authenticator reported. Without
// this the clone-detection check in the Guard compares against a stale value
// forever and stops meaning anything.
func (s *Credentials) UpdateSignCount(id string, count uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.items[id]
	if !ok {
		return ErrNoCredential
	}
	c.SignCount = count
	s.items[id] = c
	return nil
}

func encodeChallenge(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
