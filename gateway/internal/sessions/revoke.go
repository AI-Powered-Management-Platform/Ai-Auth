// Package sessions decides whether a still-valid token may still be used.
//
// A signature proves a token was issued. It says nothing about whether the
// user was fired, the device was wiped, or the session was revoked a minute
// ago. Without a check on every request, a revoked session survives until it
// expires — the gap threat-model T11 names.
package sessions

import (
	"sync"
	"time"
)

// Revocations answers "is this still allowed?" for every authenticated
// request.
//
// Two levels, because they answer different questions cheaply:
//   - a jti set kills one specific token
//   - a per-subject cutoff kills every token issued before an instant, which
//     is what "log out everywhere" and "this account is compromised" mean.
//     Storing one timestamp per subject beats enumerating their tokens.
//
// In-memory for v1. The Postgres/Redis implementation keeps this interface:
// Redis holds the fast pre-check, Postgres remains the authority, and a
// Redis miss never turns into an allow.
type Revocations struct {
	mu       sync.RWMutex
	tokens   map[string]time.Time // jti -> forget-after
	subjects map[subjectKey]time.Time
	tenants  map[string]time.Time
	now      func() time.Time
}

type subjectKey struct {
	tenant  string
	subject string
}

func NewRevocations() *Revocations {
	return &Revocations{
		tokens:   make(map[string]time.Time),
		subjects: make(map[subjectKey]time.Time),
		tenants:  make(map[string]time.Time),
		now:      time.Now,
	}
}

// RevokeToken kills one token. forgetAfter should be the token's expiry:
// once it would have expired anyway, remembering it wastes space.
func (r *Revocations) RevokeToken(jti string, forgetAfter time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[jti] = forgetAfter
	r.sweepLocked()
}

// RevokeSubject kills every token this subject holds. Later logins are
// unaffected: the cutoff is an instant, not a ban.
func (r *Revocations) RevokeSubject(tenantID, subjectID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subjects[subjectKey{tenantID, subjectID}] = r.now()
}

// RevokeTenant kills every token in a tenant. The blunt instrument for a
// compromised organisation.
func (r *Revocations) RevokeTenant(tenantID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenants[tenantID] = r.now()
}

// IsRevoked reports whether a token may still be used. issuedAt comes from
// the verified token, so a caller cannot lower it to escape a cutoff.
//
// Checks run cheapest first, and every one is a denial: there is no path
// through this function that turns an unknown state into permission.
func (r *Revocations) IsRevoked(jti, tenantID, subjectID string, issuedAt time.Time) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, dead := r.tokens[jti]; dead {
		return true
	}
	// A token issued before a cutoff is dead; one issued after is a fresh
	// login and must keep working.
	if cutoff, ok := r.subjects[subjectKey{tenantID, subjectID}]; ok && !issuedAt.After(cutoff) {
		return true
	}
	if cutoff, ok := r.tenants[tenantID]; ok && !issuedAt.After(cutoff) {
		return true
	}
	return false
}

// sweepLocked drops jti entries whose tokens have expired anyway. Subject
// and tenant cutoffs are kept: they are one small entry each and dropping
// one would resurrect every token it was killing.
func (r *Revocations) sweepLocked() {
	now := r.now()
	for jti, forget := range r.tokens {
		if now.After(forget) {
			delete(r.tokens, jti)
		}
	}
}

// Len reports tracked revocations. Metrics and tests only.
func (r *Revocations) Len() (tokens, subjects, tenants int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tokens), len(r.subjects), len(r.tenants)
}
