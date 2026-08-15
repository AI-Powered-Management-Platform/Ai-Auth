package oidc

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/tokens"
)

func TestMetadataAdvertisesOnlyWhatIsSupported(t *testing.T) {
	m := NewMetadata("https://auth.example.com")
	checks := []struct {
		name string
		got  []string
		want string
	}{
		{"response_types", m.ResponseTypesSupported, "code"},
		{"grant_types", m.GrantTypesSupported, "authorization_code"},
		{"pkce", m.CodeChallengeMethodsSupported, "S256"},
		{"signing", m.IDTokenSigningAlgValuesSupported, "ES256"},
	}
	for _, c := range checks {
		if len(c.got) != 1 || c.got[0] != c.want {
			t.Fatalf("%s = %v, want exactly [%s]", c.name, c.got, c.want)
		}
	}
}

func TestMetadataNeverAdvertisesAWeakOption(t *testing.T) {
	body, err := json.Marshal(NewMetadata("https://auth.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(body)
	for _, forbidden := range []string{
		`"plain"`, `"token"`, `"id_token"`, `"password"`,
		`"HS256"`, `"RS256"`, "client_secret_basic", "client_secret_post",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("metadata advertises %s:\n%s", forbidden, doc)
		}
	}
}

func TestDiscoveryEndpointServesTheDocument(t *testing.T) {
	d := &Discovery{Meta: NewMetadata("https://auth.example.com")}
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var m Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.TokenEndpoint != "https://auth.example.com/token" {
		t.Fatalf("token_endpoint = %q", m.TokenEndpoint)
	}
}

func TestJWKSPublishesPublicMaterialOnly(t *testing.T) {
	key, err := tokens.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	set := NewJWKS(map[string]*ecdsa.PublicKey{"key-1": &key.PublicKey})
	rec := httptest.NewRecorder()
	(&JWKS{Keys: set.Keys}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	var parsed map[string][]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	for _, k := range parsed["keys"] {
		// "d" is the private scalar. Its presence is total compromise.
		if _, leaked := k["d"]; leaked {
			t.Fatal("private scalar published in JWKS")
		}
	}
	priv := string(key.D.FillBytes(make([]byte, 32)))
	if strings.Contains(rec.Body.String(), priv) {
		t.Fatal("private key material found in the published set")
	}
}

func TestJWKSCarriesTheFieldsClientsNeed(t *testing.T) {
	key, _ := tokens.GenerateKey()
	set := NewJWKS(map[string]*ecdsa.PublicKey{"key-1": &key.PublicKey})
	if len(set.Keys) != 1 {
		t.Fatal("expected one key")
	}
	k := set.Keys[0]
	if k.Kid != "key-1" || k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" || k.Use != "sig" {
		t.Fatalf("incomplete JWK: %+v", k)
	}
	if k.X == "" || k.Y == "" {
		t.Fatal("coordinates missing")
	}
}

func TestJWKSSupportsMultipleKeysForRotation(t *testing.T) {
	// Both keys must be present during an overlap, or every token signed by
	// the outgoing key fails the moment the new one appears.
	k1, _ := tokens.GenerateKey()
	k2, _ := tokens.GenerateKey()
	set := NewJWKS(map[string]*ecdsa.PublicKey{"old": &k1.PublicKey, "new": &k2.PublicKey})
	if len(set.Keys) != 2 {
		t.Fatalf("rotation needs both keys published, got %d", len(set.Keys))
	}
}

func TestDiscoveryAndJWKSRefuseNonGET(t *testing.T) {
	d := &Discovery{Meta: NewMetadata("https://auth.example.com")}
	j := &JWKS{}
	for _, h := range []http.Handler{d, j} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("got %d, want 405", rec.Code)
		}
	}
}
