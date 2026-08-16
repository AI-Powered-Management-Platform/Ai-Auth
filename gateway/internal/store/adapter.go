package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/oidc"
)

// CodeAdapter presents the Postgres code store through the interface the
// OIDC handlers expect. It exists so the handlers stay ignorant of storage,
// and so the context and timeout policy live in one place rather than being
// threaded through every HTTP signature.
type CodeAdapter struct {
	codes *Codes
	// Timeout bounds every database call. A store that hangs must become a
	// failed login, not a stuck request holding a connection.
	Timeout time.Duration
}

func NewCodeAdapter(c *Codes) *CodeAdapter {
	return &CodeAdapter{codes: c, Timeout: 2 * time.Second}
}

func (a *CodeAdapter) Issue(g oidc.Grant) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(raw)

	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout)
	defer cancel()
	err := a.codes.Insert(ctx, code, Grant{
		ClientID:      g.ClientID,
		RedirectURI:   g.RedirectURI,
		Scope:         g.Scope,
		Nonce:         g.Nonce,
		CodeChallenge: g.CodeChallenge,
		SubjectID:     g.SubjectID,
		TenantID:      g.TenantID,
		AuthTime:      g.AuthTime,
	}, time.Now().Add(oidc.CodeTTL))
	if err != nil {
		return "", err
	}
	return code, nil
}

func (a *CodeAdapter) Redeem(code, clientID, redirectURI string) (*oidc.Grant, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout)
	defer cancel()
	g, err := a.codes.Redeem(ctx, code, clientID, redirectURI)
	if errors.Is(err, ErrNotFound) {
		// Collapse to the OIDC layer's single refusal: the endpoint must not
		// distinguish unknown from expired from wrong-client.
		return nil, oidc.ErrCodeUnknown
	}
	if err != nil {
		return nil, err
	}
	return &oidc.Grant{
		ClientID:      g.ClientID,
		RedirectURI:   g.RedirectURI,
		Scope:         g.Scope,
		Nonce:         g.Nonce,
		CodeChallenge: g.CodeChallenge,
		SubjectID:     g.SubjectID,
		TenantID:      g.TenantID,
		AuthTime:      g.AuthTime,
	}, nil
}

// RevocationChecker is what the session middleware needs. An interface for
// the same reason as Codes: the middleware should not know where the answer
// comes from.
type RevocationChecker interface {
	IsRevoked(jti, tenantID, subjectID string, issuedAt time.Time) bool
}

// RevocationAdapter presents the Postgres revocation store to the middleware.
//
// The signature returns a bare bool with no error, deliberately: there is no
// caller who could do anything useful with a database error except deny, so
// the decision is made here rather than pushed outward where someone might
// log it and continue.
type RevocationAdapter struct {
	revs    *Revocations
	Timeout time.Duration
	OnError func(error)
}

func NewRevocationAdapter(r *Revocations) *RevocationAdapter {
	return &RevocationAdapter{revs: r, Timeout: 500 * time.Millisecond}
}

// IsRevoked answers the middleware's question, and answers "revoked" when it
// cannot answer at all.
//
// This is the fail-closed matrix applied to the database: if the store is
// unreachable, we do not know whether this session was killed, and an
// unknown answer must never become permission. The cost is that a database
// outage logs everyone out; the alternative is that a database outage
// silently un-revokes every compromised session, which is worse.
func (a *RevocationAdapter) IsRevoked(jti, tenantID, subjectID string, issuedAt time.Time) bool {
	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout)
	defer cancel()

	revoked, err := a.revs.IsRevoked(ctx, jti, tenantID, subjectID, issuedAt)
	if err != nil {
		if a.OnError != nil {
			a.OnError(err)
		}
		return true
	}
	return revoked
}
