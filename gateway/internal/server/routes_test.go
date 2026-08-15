package server

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/oidc"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/tokens"
)

func oidcServer(t *testing.T) http.Handler {
	t.Helper()
	key, err := tokens.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := tokens.NewSigner("https://auth.example.com", "key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{
		Version:     "test",
		Issuer:      "https://auth.example.com",
		Audience:    "api",
		Signer:      signer,
		SigningKeys: map[string]*ecdsa.PublicKey{"key-1": &key.PublicKey},
		Clients: func(id string) (oidc.Client, bool) {
			if id != "app" {
				return oidc.Client{}, false
			}
			return oidc.Client{ID: "app", RedirectURIs: []string{"https://app.example.com/cb"}}, true
		},
		LoginURL: "/login",
	})
}

func TestDiscoveryIsReachable(t *testing.T) {
	rec := httptest.NewRecorder()
	oidcServer(t).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var m oidc.Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Issuer != "https://auth.example.com" {
		t.Fatalf("issuer = %q", m.Issuer)
	}
}

func TestJWKSIsReachable(t *testing.T) {
	rec := httptest.NewRecorder()
	oidcServer(t).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if !json.Valid(rec.Body.Bytes()) {
		t.Fatal("jwks is not valid json")
	}
}

func TestAuthorizeIsReachableAndRedirects(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"+
			"&response_type=code&scope=openid&code_challenge=abc&code_challenge_method=S256", nil)
	oidcServer(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("got %d, want 302: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenRejectsGET(t *testing.T) {
	// The mux registers POST only, so a GET must not reach the handler.
	rec := httptest.NewRecorder()
	oidcServer(t).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/token", nil))
	if rec.Code == http.StatusOK {
		t.Fatal("GET /token must not succeed")
	}
}

func TestOIDCRoutesAreAbsentWithoutASigner(t *testing.T) {
	// A half-configured token endpoint must not exist: an endpoint that 500s
	// still looks like an endpoint to a client building against discovery.
	h := New(Config{Version: "test"})
	for _, path := range []string{"/authorize", "/token", "/.well-known/openid-configuration", "/.well-known/jwks.json"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d without a signer, want 404", path, rec.Code)
		}
	}
}

func TestSecurityHeadersAreOnEveryResponse(t *testing.T) {
	h := oidcServer(t)
	for _, path := range []string{"/healthz", "/.well-known/jwks.json", "/nope"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		for header, want := range map[string]string{
			"X-Frame-Options":        "DENY",
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "no-referrer",
		} {
			if got := rec.Header().Get(header); got != want {
				t.Fatalf("%s on %s = %q, want %q", header, path, got, want)
			}
		}
		if rec.Header().Get("Strict-Transport-Security") == "" {
			t.Fatalf("HSTS missing on %s", path)
		}
	}
}
