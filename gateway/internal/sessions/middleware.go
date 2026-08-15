package sessions

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/dpop"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/tokens"
)

type contextKey struct{}

// FromContext returns the verified claims a handler may rely on. Its
// presence means every check below passed.
func FromContext(ctx context.Context) (*tokens.Claims, bool) {
	c, ok := ctx.Value(contextKey{}).(*tokens.Claims)
	return c, ok
}

// Authenticator guards protected routes.
type Authenticator struct {
	Tokens      *tokens.Verifier
	DPoP        *dpop.Verifier
	Revocations *Revocations
	Audience    string
	// BaseURL is this server's own address, used to rebuild the URI a proof
	// must be bound to. Taken from configuration, never from the request:
	// Host is attacker-controlled, and trusting it would let a proof made
	// for another host be replayed here.
	BaseURL string
	Log     *slog.Logger
}

// Require wraps a handler so it only runs for a live, bound, unrevoked
// session.
//
// Order is deliberate and cheapest-first: parse, verify signature, verify
// proof, then ask about revocation. An unsigned token never reaches the
// revocation store, so garbage traffic cannot turn into lookups.
func (a *Authenticator) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := dpopToken(r.Header.Get("Authorization"))
		if !ok {
			// The scheme must be DPoP. A Bearer token is not a shape this
			// system accepts, even if it would otherwise verify.
			a.challenge(w, "invalid_token", "a DPoP-bound access token is required")
			return
		}

		claims, err := a.Tokens.Verify(raw, a.Audience)
		if err != nil {
			a.log().Info("token refused", "reason", err.Error())
			a.challenge(w, "invalid_token", "token is not valid")
			return
		}

		// A token without a confirmation claim is a bearer token wearing a
		// DPoP header. Refusing it closes the downgrade.
		if claims.Confirm == nil || claims.Confirm.JKT == "" {
			a.log().Warn("unbound token presented", "sub", claims.Subject)
			a.challenge(w, "invalid_token", "token is not sender-constrained")
			return
		}

		proof := r.Header.Get("DPoP")
		if proof == "" {
			a.challenge(w, "invalid_dpop_proof", "a DPoP proof is required")
			return
		}
		if _, err := a.DPoP.Verify(proof, r.Method, a.BaseURL+r.URL.Path, raw, claims.Confirm.JKT); err != nil {
			a.log().Info("proof refused", "reason", err.Error())
			a.challenge(w, "invalid_dpop_proof", "proof is not valid")
			return
		}

		if a.Revocations.IsRevoked(claims.JTI, claims.TenantID, claims.Subject,
			time.Unix(claims.IssuedAt, 0)) {
			// Revocation is deliberately indistinguishable from an invalid
			// token: whether a session existed is not information an
			// attacker holding a stolen token should gain.
			a.log().Info("revoked session refused", "sub", claims.Subject)
			a.challenge(w, "invalid_token", "token is not valid")
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, claims)))
	})
}

// dpopToken extracts the token from an Authorization header, requiring the
// DPoP scheme.
func dpopToken(header string) (string, bool) {
	const scheme = "dpop "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	token := strings.TrimSpace(header[len(scheme):])
	return token, token != ""
}

func (a *Authenticator) challenge(w http.ResponseWriter, code, desc string) {
	w.Header().Set("WWW-Authenticate",
		`DPoP algs="ES256", error="`+code+`", error_description="`+desc+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
}

func (a *Authenticator) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}
