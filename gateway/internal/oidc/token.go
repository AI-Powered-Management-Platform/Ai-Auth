package oidc

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/dpop"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/tokens"
)

// AccessTokenTTL is minutes, not hours. A bearer-shaped credential's blast
// radius is its lifetime; DPoP shrinks the value of a stolen one, and this
// shrinks the window (threat model T1, Tier 2).
const AccessTokenTTL = 10 * time.Minute

// Token serves the token endpoint.
type Token struct {
	Codes    *CodeStore
	Signer   *tokens.Signer
	Audience string
	// DPoP verifies the proof a client sends with its exchange. Absent means
	// tokens are issued unbound, which is only acceptable in development —
	// an unbound token is a bearer token, and bearer is not a shape this
	// system is supposed to issue.
	DPoP   *dpop.Verifier
	Issuer string
	Log    *slog.Logger
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type tokenError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (t *Token) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Token requests are POST only: a GET would put a code and verifier into
	// browser history, server logs, and Referer headers (T1 Path C).
	if r.Method != http.MethodPost {
		t.fail(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		t.fail(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}

	if r.PostForm.Get("grant_type") != "authorization_code" {
		t.fail(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	code := r.PostForm.Get("code")
	clientID := r.PostForm.Get("client_id")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")

	if code == "" || clientID == "" || redirectURI == "" || verifier == "" {
		t.fail(w, http.StatusBadRequest, "invalid_request", "missing required parameter")
		return
	}

	// Redeeming consumes the code even when the rest of this fails: one
	// attempt per code, never an oracle.
	grant, err := t.Codes.Redeem(code, clientID, redirectURI)
	if err != nil {
		// Every redemption failure reports the same thing. Distinguishing
		// "unknown code" from "wrong client" would let an attacker with a
		// stolen code learn who it belongs to.
		t.log().Warn("code redemption refused", "reason", err.Error(), "client_id", clientID)
		t.fail(w, http.StatusBadRequest, "invalid_grant", "authorization code is not valid")
		return
	}

	if err := VerifyPKCE(verifier, grant.CodeChallenge); err != nil {
		t.log().Warn("pkce refused", "client_id", clientID)
		t.fail(w, http.StatusBadRequest, "invalid_grant", "authorization code is not valid")
		return
	}

	// The DPoP proof at this endpoint carries no access token yet: it proves
	// possession of the key the issued token will be bound to.
	var confirm *tokens.Confirm
	if t.DPoP != nil {
		proofJWT := r.Header.Get("DPoP")
		if proofJWT == "" {
			// RFC 9449 §5.2: the challenge tells the client to retry with a
			// proof rather than leaving it to guess.
			w.Header().Set("WWW-Authenticate", `DPoP algs="ES256"`)
			t.fail(w, http.StatusBadRequest, "invalid_dpop_proof", "a DPoP proof is required")
			return
		}
		proof, err := t.DPoP.Verify(proofJWT, r.Method, t.Issuer+"/token", "", "")
		if err != nil {
			t.log().Warn("dpop proof refused", "client_id", clientID, "reason", err.Error())
			t.fail(w, http.StatusBadRequest, "invalid_dpop_proof", "proof is not valid")
			return
		}
		confirm = &tokens.Confirm{JKT: proof.Thumbprint}
	}

	token, err := t.Signer.Issue(tokens.Claims{
		Subject:  grant.SubjectID,
		Audience: t.Audience,
		TenantID: grant.TenantID,
		Scope:    grant.Scope,
		Confirm:  confirm,
	}, AccessTokenTTL)
	if err != nil {
		t.log().Error("token issuance", "err", err)
		t.fail(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	t.write(w, http.StatusOK, tokenResponse{
		AccessToken: token,
		TokenType:   "DPoP",
		ExpiresIn:   int(AccessTokenTTL.Seconds()),
		Scope:       grant.Scope,
	})
}

func (t *Token) fail(w http.ResponseWriter, status int, code, desc string) {
	t.write(w, status, tokenError{Error: code, Description: desc})
}

func (t *Token) write(w http.ResponseWriter, status int, body any) {
	// Tokens must never be cached by anything between here and the client.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.log().Error("write token response", "err", err)
	}
}

func (t *Token) log() *slog.Logger {
	if t.Log != nil {
		return t.Log
	}
	return slog.Default()
}
