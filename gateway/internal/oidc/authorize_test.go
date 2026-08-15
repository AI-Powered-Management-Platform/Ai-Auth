package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
)

const registered = "https://app.example.com/callback"

func testLookup(id string) (Client, bool) {
	if id != "app" {
		return Client{}, false
	}
	return Client{ID: "app", RedirectURIs: []string{registered}}, true
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// valid returns a request with every rail satisfied, so each test can break
// exactly one thing.
func valid() url.Values {
	return url.Values{
		"client_id":             {"app"},
		"redirect_uri":          {registered},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {challengeFor(strings.Repeat("a", 64))},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
	}
}

func TestAValidRequestPasses(t *testing.T) {
	req, err := ValidateAuthz(valid(), testLookup)
	if err != nil {
		t.Fatal(err)
	}
	if req.ClientID != "app" || req.State != "xyz" {
		t.Fatal("validated request lost its fields")
	}
}

func TestRedirectMustMatchExactly(t *testing.T) {
	// Every one of these has been a real-world token theft.
	for _, bad := range []string{
		"https://app.example.com/callback/",                     // trailing slash
		"https://app.example.com/callback/extra",                // path suffix
		"https://app.example.com/callback?x=1",                  // added query
		"https://evil.com/x?u=https://app.example.com/callback", // embedded
		"https://app.example.com.evil.com/callback",             // suffix domain
		"http://app.example.com/callback",                       // downgraded scheme
		"",                                                      // absent
	} {
		p := valid()
		p.Set("redirect_uri", bad)
		if _, err := ValidateAuthz(p, testLookup); !errors.Is(err, ErrRedirectMismatch) {
			t.Fatalf("redirect %q was accepted", bad)
		}
	}
}

func TestUnknownClientIsRefused(t *testing.T) {
	p := valid()
	p.Set("client_id", "nobody")
	if _, err := ValidateAuthz(p, testLookup); !errors.Is(err, ErrUnknownClient) {
		t.Fatal("unknown client accepted")
	}
}

func TestOnlyCodeFlowIsSupported(t *testing.T) {
	for _, rt := range []string{"token", "id_token", "code token", "", "CODE"} {
		p := valid()
		p.Set("response_type", rt)
		if _, err := ValidateAuthz(p, testLookup); !errors.Is(err, ErrUnsupportedType) {
			t.Fatalf("response_type %q accepted: tokens must not travel via the browser", rt)
		}
	}
}

func TestPKCEIsMandatory(t *testing.T) {
	p := valid()
	p.Del("code_challenge")
	if _, err := ValidateAuthz(p, testLookup); !errors.Is(err, ErrPKCERequired) {
		t.Fatal("a request without PKCE was accepted")
	}
}

func TestPlainPKCEIsRefused(t *testing.T) {
	// Absent method means "plain" per RFC 7636; both must be refused.
	for _, method := range []string{"plain", "", "s256", "S512"} {
		p := valid()
		p.Set("code_challenge_method", method)
		if _, err := ValidateAuthz(p, testLookup); !errors.Is(err, ErrPKCEMethod) {
			t.Fatalf("method %q accepted", method)
		}
	}
}

func TestMalformedChallengeIsRefused(t *testing.T) {
	p := valid()
	p.Set("code_challenge", "not base64url!!")
	if _, err := ValidateAuthz(p, testLookup); !errors.Is(err, ErrPKCEMalformed) {
		t.Fatal("malformed challenge accepted")
	}
}

func TestScopeIsRequired(t *testing.T) {
	p := valid()
	p.Del("scope")
	if _, err := ValidateAuthz(p, testLookup); !errors.Is(err, ErrScopeMissing) {
		t.Fatal("missing scope accepted")
	}
}

func TestRedirectIsCheckedBeforeAnythingReportable(t *testing.T) {
	// A request that is wrong in two ways must fail on the redirect, or the
	// endpoint could be turned into an open redirector for the other error.
	p := valid()
	p.Set("redirect_uri", "https://evil.com/steal")
	p.Set("response_type", "token")
	if _, err := ValidateAuthz(p, testLookup); !errors.Is(err, ErrRedirectMismatch) {
		t.Fatal("redirect must be validated before any error can be redirected")
	}
}

func TestPKCEVerifierMatches(t *testing.T) {
	v := strings.Repeat("a", 64)
	if err := VerifyPKCE(v, challengeFor(v)); err != nil {
		t.Fatal(err)
	}
}

func TestPKCEWrongVerifierIsRefused(t *testing.T) {
	// The interception case: an attacker holding the code but not the verifier.
	v := strings.Repeat("a", 64)
	if err := VerifyPKCE(strings.Repeat("b", 64), challengeFor(v)); !errors.Is(err, ErrPKCEMismatch) {
		t.Fatal("a stolen code must be unusable without the verifier")
	}
}

func TestPKCEVerifierLengthIsEnforced(t *testing.T) {
	for _, v := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 129)} {
		if err := VerifyPKCE(v, challengeFor(v)); !errors.Is(err, ErrPKCEVerifierLength) {
			t.Fatalf("verifier of length %d accepted", len(v))
		}
	}
}

func TestErrorRedirectPreservesStateAndPath(t *testing.T) {
	got, err := RedirectWithError(registered, "xyz", "access_denied", "user refused")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	if u.Host != "app.example.com" || u.Path != "/callback" {
		t.Fatalf("redirect target changed: %s", got)
	}
	if u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "xyz" {
		t.Fatalf("error redirect lost fields: %s", got)
	}
}
