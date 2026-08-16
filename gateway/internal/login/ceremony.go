package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	cryptov1 "github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/gen/aiauth/crypto/v1"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/guard"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/oidc"
)

// Verifier is the Guard call this package needs. An interface rather than
// the concrete client so the ceremony can be tested without a TLS listener.
type Verifier interface {
	VerifyPasskey(ctx context.Context, call guard.Call, rpID, origin string,
		challenge []byte, credential *cryptov1.StoredCredential,
		assertion *cryptov1.Assertion) (*cryptov1.VerifyAssertionResponse, error)
}

// Ceremony serves the passkey login exchange.
type Ceremony struct {
	Guard       Verifier
	Challenges  *Challenges
	Credentials *Credentials
	Pending     *oidc.PendingStore
	Codes       oidc.Codes
	RPID        string
	Origin      string
	Log         *slog.Logger
}

type beginResponse struct {
	Challenge string `json:"challenge"`
	RPID      string `json:"rpId"`
	Timeout   int    `json:"timeout"`
}

type finishRequest struct {
	RID               string `json:"rid"`
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

type finishResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// Begin issues a challenge for a pending authorization request.
func (c *Ceremony) Begin(w http.ResponseWriter, r *http.Request) {
	rid := r.URL.Query().Get("rid")
	if rid == "" {
		c.fail(w, http.StatusBadRequest, "missing request id")
		return
	}
	// The pending request is only peeked at here, never consumed: a user who
	// abandons the prompt and retries must still be able to finish.
	challenge, err := c.Challenges.Issue(rid)
	if err != nil {
		c.log().Error("challenge", "err", err)
		c.fail(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	c.write(w, http.StatusOK, beginResponse{
		Challenge: encodeChallenge(challenge),
		RPID:      c.RPID,
		Timeout:   int(ChallengeTTL / time.Millisecond),
	})
}

// Finish verifies the assertion and, on success, issues an authorization
// code and returns where to send the browser.
func (c *Ceremony) Finish(w http.ResponseWriter, r *http.Request) {
	var req finishRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		c.fail(w, http.StatusBadRequest, "malformed request")
		return
	}

	// Challenge first: it is consumed whether or not anything below
	// succeeds, so one challenge buys exactly one attempt.
	challenge, err := c.Challenges.Take(req.RID)
	if err != nil {
		c.deny(w, "no active challenge")
		return
	}

	cred, err := c.Credentials.Get(req.CredentialID)
	if err != nil {
		// An unknown credential and a failed signature return the same
		// answer: whether a credential exists is not something an
		// unauthenticated caller may learn.
		c.deny(w, "credential lookup failed")
		return
	}

	authData, err1 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	clientData, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	sig, err3 := base64.RawURLEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		c.deny(w, "malformed assertion encoding")
		return
	}

	resp, err := c.Guard.VerifyPasskey(r.Context(),
		guard.Call{TenantID: cred.TenantID, SubjectID: cred.SubjectID},
		c.RPID, c.Origin, challenge,
		&cryptov1.StoredCredential{CosePublicKey: cred.PublicKey, SignCount: cred.SignCount},
		&cryptov1.Assertion{
			AuthenticatorData: authData,
			ClientDataJson:    clientData,
			Signature:         sig,
		})
	if err != nil {
		// The Guard being unreachable must never become a login: no Guard
		// means nobody gets in.
		c.log().Error("guard unreachable during login", "err", err)
		c.fail(w, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}
	if resp.GetVerdict() != cryptov1.VerifyAssertionResponse_VERDICT_VERIFIED {
		// The Guard's reason names the failed check; it goes to the log for
		// operators, never to the caller.
		c.log().Warn("assertion rejected", "reason", resp.GetReason())
		c.deny(w, "assertion rejected")
		return
	}

	// Persist the counter so clone detection compares against the newest
	// value rather than a stale one forever.
	if n := resp.GetNewSignCount(); n != 0 {
		if err := c.Credentials.UpdateSignCount(cred.ID, n); err != nil {
			c.log().Error("sign count update", "err", err)
		}
	}

	// Only now is the pending request consumed: authentication succeeded.
	authz, ok := c.Pending.Take(req.RID)
	if !ok {
		c.deny(w, "authorization request expired")
		return
	}

	code, err := c.Codes.Issue(oidc.Grant{
		ClientID:      authz.ClientID,
		RedirectURI:   authz.RedirectURI,
		Scope:         authz.Scope,
		Nonce:         authz.Nonce,
		CodeChallenge: authz.CodeChallenge,
		SubjectID:     cred.SubjectID,
		TenantID:      cred.TenantID,
		AuthTime:      time.Now(),
	})
	if err != nil {
		c.log().Error("code issue", "err", err)
		c.fail(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}

	target, err := oidc.RedirectWithCode(authz.RedirectURI, authz.State, code)
	if err != nil {
		c.fail(w, http.StatusBadRequest, "invalid redirect")
		return
	}
	c.write(w, http.StatusOK, finishResponse{RedirectTo: target})
}

// deny is the single shape every authentication failure takes. Callers learn
// that it failed, never which check failed — the difference is what turns a
// login endpoint into an enumeration oracle.
func (c *Ceremony) deny(w http.ResponseWriter, internalReason string) {
	c.log().Info("login denied", "reason", internalReason)
	c.fail(w, http.StatusUnauthorized, "authentication failed")
}

func (c *Ceremony) fail(w http.ResponseWriter, status int, msg string) {
	c.write(w, status, map[string]string{"error": msg})
}

func (c *Ceremony) write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (c *Ceremony) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}
