package oidc

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// Metadata is the authorization server metadata document (RFC 8414 /
// OpenID Discovery). It advertises only what is actually supported: a
// capability listed here and refused at runtime is worse than an omission,
// because clients build against it.
type Metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	DPoPSigningAlgValuesSupported     []string `json:"dpop_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
}

// NewMetadata builds the document from the issuer. Every list is closed:
// S256 without "plain", "code" without implicit or hybrid, ES256 without
// RS256 or HS256. The document is a promise, and these are the promises the
// endpoints actually keep.
func NewMetadata(issuer string) Metadata {
	return Metadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/authorize",
		TokenEndpoint:                     issuer + "/token",
		JWKSURI:                           issuer + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		TokenEndpointAuthMethodsSupported: []string{"none", "private_key_jwt"},
		DPoPSigningAlgValuesSupported:     []string{"ES256"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		SubjectTypesSupported:             []string{"public"},
	}
}

// Discovery serves the metadata document.
type Discovery struct {
	Meta Metadata
}

func (d *Discovery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Discovery is public and stable; a short cache spares the endpoint from
	// every client refetching on every login.
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(d.Meta)
}

// JWK is a public key in JWK form. There is deliberately no field in this
// struct that could hold private material.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []JWK `json:"keys"`
}

// JWKS serves the public signing keys.
type JWKS struct {
	Keys []JWK
}

// NewJWKS builds a key set. Taking *ecdsa.PublicKey rather than the private
// key means a careless caller cannot hand this the wrong half.
func NewJWKS(keys map[string]*ecdsa.PublicKey) JWKS {
	set := JWKS{}
	for kid, k := range keys {
		set.Keys = append(set.Keys, JWK{
			Kty: "EC",
			Crv: "P-256",
			Kid: kid,
			Use: "sig",
			Alg: "ES256",
			X:   base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, 32))),
			Y:   base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, 32))),
		})
	}
	return set
}

func (j *JWKS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	// Short enough that a rotation propagates in minutes, not hours.
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(jwkSet{Keys: j.Keys})
}
