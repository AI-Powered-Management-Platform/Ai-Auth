package sessions

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/dpop"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/tokens"
)

const (
	issuer   = "https://auth.example.com"
	audience = "api"
	path     = "/me"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type env struct {
	auth      *Authenticator
	clientKey *ecdsa.PrivateKey
	token     string
	revs      *Revocations
}

func setup(t *testing.T) *env {
	t.Helper()
	signKey, err := tokens.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := tokens.NewSigner(issuer, "k1", signKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := tokens.NewVerifier(issuer, &signKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Issue(tokens.Claims{
		Subject: "u1", Audience: audience, TenantID: "t1",
		JTI: "jti-1", Confirm: &tokens.Confirm{JKT: dpop.Thumbprint(&clientKey.PublicKey)},
	}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	revs := NewRevocations()
	return &env{
		auth: &Authenticator{
			Tokens: verifier, DPoP: dpop.NewVerifier(), Revocations: revs,
			Audience: audience, BaseURL: issuer,
		},
		clientKey: clientKey, token: token, revs: revs,
	}
}

// proofFor builds a real DPoP proof for this request.
func proofFor(t *testing.T, key *ecdsa.PrivateKey, method, uri, token, jti string) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256",
		"jwk": map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": b64(key.PublicKey.X.FillBytes(make([]byte, 32))),
			"y": b64(key.PublicKey.Y.FillBytes(make([]byte, 32))),
		},
	})
	ath := sha256.Sum256([]byte(token))
	pl, _ := json.Marshal(map[string]any{
		"jti": jti, "htm": method, "htu": uri,
		"iat": time.Now().Unix(), "ath": b64(ath[:]),
	})
	signing := b64(hdr) + "." + b64(pl)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64(sig)
}

func (e *env) call(t *testing.T, token, proof string) *httptest.ResponseRecorder {
	t.Helper()
	h := e.auth.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := FromContext(r.Context())
		if !ok {
			t.Error("handler ran without claims in context")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(c.Subject))
	}))
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "DPoP "+token)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (e *env) goodProof(t *testing.T, jti string) string {
	return proofFor(t, e.clientKey, http.MethodGet, issuer+path, e.token, jti)
}

func TestAValidBoundRequestReachesTheHandler(t *testing.T) {
	e := setup(t)
	rec := e.call(t, e.token, e.goodProof(t, "p1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	if rec.Body.String() != "u1" {
		t.Fatal("claims did not reach the handler")
	}
}

func TestARevokedTokenIsRefused(t *testing.T) {
	e := setup(t)
	e.revs.RevokeToken("jti-1", time.Now().Add(time.Hour))
	if rec := e.call(t, e.token, e.goodProof(t, "p2")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 — a revoked token must die immediately", rec.Code)
	}
}

func TestRevokingTheSubjectEndsTheSessionNow(t *testing.T) {
	// The T11 case: not at expiry, now.
	e := setup(t)
	if rec := e.call(t, e.token, e.goodProof(t, "p3")); rec.Code != http.StatusOK {
		t.Fatal("setup: the session should start valid")
	}
	e.revs.RevokeSubject("t1", "u1")
	if rec := e.call(t, e.token, e.goodProof(t, "p4")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 after revocation", rec.Code)
	}
}

func TestRevocationIsIndistinguishableFromAnInvalidToken(t *testing.T) {
	// Whether a session existed is not information a thief should gain.
	e := setup(t)
	e.revs.RevokeToken("jti-1", time.Now().Add(time.Hour))
	revoked := e.call(t, e.token, e.goodProof(t, "p5"))

	e2 := setup(t)
	garbage := e2.call(t, "not.a.token", e2.goodProof(t, "p6"))

	if revoked.Code != garbage.Code {
		t.Fatalf("status differs: revoked %d, invalid %d", revoked.Code, garbage.Code)
	}
	if revoked.Header().Get("WWW-Authenticate") != garbage.Header().Get("WWW-Authenticate") {
		t.Fatalf("challenge differs:\n revoked: %s\n invalid: %s",
			revoked.Header().Get("WWW-Authenticate"), garbage.Header().Get("WWW-Authenticate"))
	}
}

func TestAStolenTokenWithoutTheKeyIsRefused(t *testing.T) {
	e := setup(t)
	thief, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof := proofFor(t, thief, http.MethodGet, issuer+path, e.token, "p7")
	if rec := e.call(t, e.token, proof); rec.Code != http.StatusUnauthorized {
		t.Fatal("a stolen token must be useless without its key")
	}
}

func TestABearerSchemeIsRefused(t *testing.T) {
	// Bearer is not a shape this system accepts, even for a valid token.
	e := setup(t)
	h := e.auth.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run")
	}))
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("DPoP", e.goodProof(t, "p8"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}

func TestAnUnboundTokenIsRefused(t *testing.T) {
	// A token with no cnf claim is a bearer token wearing a DPoP header.
	signKey, _ := tokens.GenerateKey()
	signer, _ := tokens.NewSigner(issuer, "k1", signKey)
	verifier, _ := tokens.NewVerifier(issuer, &signKey.PublicKey)
	unbound, err := signer.Issue(tokens.Claims{
		Subject: "u1", Audience: audience, TenantID: "t1", JTI: "j",
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a := &Authenticator{
		Tokens: verifier, DPoP: dpop.NewVerifier(), Revocations: NewRevocations(),
		Audience: audience, BaseURL: issuer,
	}
	h := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run for an unbound token")
	}))
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "DPoP "+unbound)
	req.Header.Set("DPoP", proofFor(t, clientKey, http.MethodGet, issuer+path, unbound, "p9"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}

func TestAMissingProofIsRefused(t *testing.T) {
	e := setup(t)
	if rec := e.call(t, e.token, ""); rec.Code != http.StatusUnauthorized {
		t.Fatal("a bound token still needs a proof on every call")
	}
}

func TestAMissingTokenIsRefused(t *testing.T) {
	e := setup(t)
	if rec := e.call(t, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatal("no token, no access")
	}
}

func TestAProofCannotBeReplayed(t *testing.T) {
	e := setup(t)
	proof := e.goodProof(t, "same-jti")
	if rec := e.call(t, e.token, proof); rec.Code != http.StatusOK {
		t.Fatal("first call should pass")
	}
	if rec := e.call(t, e.token, proof); rec.Code != http.StatusUnauthorized {
		t.Fatal("the same proof must not work twice")
	}
}

func TestChallengesCarryTheDPoPScheme(t *testing.T) {
	// Clients need to be told how to retry, not left guessing.
	e := setup(t)
	rec := e.call(t, "", "")
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "DPoP ") {
		t.Fatalf("challenge = %q", rec.Header().Get("WWW-Authenticate"))
	}
}
