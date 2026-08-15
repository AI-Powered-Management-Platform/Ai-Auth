// Package oidc holds the authorization surface. Everything here is a safety
// rail rather than a policy setting: these are the checks with no legitimate
// reason to be disabled, so none of them is configurable.
package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
)

// Errors are typed so handlers can map them to the right OAuth error code
// without re-parsing strings.
var (
	ErrUnknownClient      = errors.New("unknown client")
	ErrRedirectMismatch   = errors.New("redirect_uri does not exactly match a registered value")
	ErrUnsupportedType    = errors.New("only response_type=code is supported")
	ErrPKCERequired       = errors.New("code_challenge is required")
	ErrPKCEMethod         = errors.New("only code_challenge_method=S256 is supported")
	ErrPKCEMalformed      = errors.New("code_challenge is not valid base64url")
	ErrPKCEVerifierLength = errors.New("code_verifier must be 43-128 characters")
	ErrPKCEMismatch       = errors.New("code_verifier does not match the challenge")
	ErrScopeMissing       = errors.New("scope is required")
)

// Client is a registered relying party. Redirect URIs are exact strings:
// no wildcards, no prefix matching, no normalisation beyond what the
// registration stored — every relaxation of this rule has produced a
// real-world token theft.
type Client struct {
	ID           string
	RedirectURIs []string
}

func (c Client) allowsRedirect(candidate string) bool {
	for _, registered := range c.RedirectURIs {
		// Constant-time is not needed here (both values are public), but
		// exactness is: compare whole strings, never prefixes.
		if registered == candidate {
			return true
		}
	}
	return false
}

// AuthzRequest is a validated authorization request. Its existence means
// every rail below has already passed.
type AuthzRequest struct {
	ClientID      string
	RedirectURI   string
	Scope         string
	State         string
	CodeChallenge string
	Nonce         string
}

// ValidateAuthz applies the rails in cheapest-first order. The client lookup
// runs first because an unknown client means nothing else is worth checking.
func ValidateAuthz(params url.Values, lookup func(string) (Client, bool)) (*AuthzRequest, error) {
	clientID := params.Get("client_id")
	client, ok := lookup(clientID)
	if !ok {
		return nil, ErrUnknownClient
	}

	redirect := params.Get("redirect_uri")
	if !client.allowsRedirect(redirect) {
		// Deliberately checked before anything else that could be reported
		// back: a mismatched redirect must never receive an error redirect,
		// or the endpoint becomes an open redirector.
		return nil, ErrRedirectMismatch
	}

	if params.Get("response_type") != "code" {
		// No implicit, no hybrid: tokens must never travel via the browser.
		return nil, ErrUnsupportedType
	}

	challenge := params.Get("code_challenge")
	if challenge == "" {
		return nil, ErrPKCERequired
	}
	// An absent method means "plain" in RFC 7636. We reject both the absence
	// and the value, because plain PKCE proves nothing an interceptor of the
	// authorization request cannot also produce.
	if params.Get("code_challenge_method") != "S256" {
		return nil, ErrPKCEMethod
	}
	if _, err := base64.RawURLEncoding.DecodeString(challenge); err != nil {
		return nil, ErrPKCEMalformed
	}

	scope := params.Get("scope")
	if scope == "" {
		return nil, ErrScopeMissing
	}

	return &AuthzRequest{
		ClientID:      client.ID,
		RedirectURI:   redirect,
		Scope:         scope,
		State:         params.Get("state"),
		CodeChallenge: challenge,
		Nonce:         params.Get("nonce"),
	}, nil
}

// VerifyPKCE checks a code_verifier against the stored challenge at token
// exchange. This is the step that makes an intercepted authorization code
// useless: the interceptor never saw the verifier.
//
// It does not stop an adversary-in-the-middle proxy that relays the whole
// flow — that is threat-model T1 Path A, answered by token binding.
func VerifyPKCE(verifier, storedChallenge string) error {
	// RFC 7636 §4.1. Length is checked before hashing so a malformed value
	// costs nothing.
	if len(verifier) < 43 || len(verifier) > 128 {
		return ErrPKCEVerifierLength
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(storedChallenge)) != 1 {
		return ErrPKCEMismatch
	}
	return nil
}

// RedirectWithError builds the error redirect for a request that has already
// passed the redirect check. Callers must never use it for ErrRedirectMismatch
// or ErrUnknownClient — those are shown to the user, never redirected.
func RedirectWithError(redirectURI, state, code, description string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("oidc: unparsable redirect: %w", err)
	}
	q := u.Query()
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
