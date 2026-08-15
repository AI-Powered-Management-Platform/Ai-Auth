// Package tokens issues and verifies access tokens.
//
// Tokens are ES256 JWTs. The signing key lives here for v1; it moves behind
// the crypto service's KMS/HSM path before any real deployment — see
// docs/key-custody.md §4, where token signing is its own hierarchy.
package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	ErrMalformed = errors.New("token is malformed")
	ErrAlgorithm = errors.New("unexpected token algorithm")
	ErrSignature = errors.New("token signature does not verify")
	ErrExpired   = errors.New("token has expired")
	ErrNotYet    = errors.New("token is not valid yet")
	ErrIssuer    = errors.New("unexpected issuer")
	ErrAudience  = errors.New("unexpected audience")
)

// Claims is the access token payload. `cnf` carries the DPoP key thumbprint,
// which is what makes a stolen token useless without its private key.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	TenantID  string   `json:"tid"`
	Scope     string   `json:"scope"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	JTI       string   `json:"jti"`
	Confirm   *Confirm `json:"cnf,omitempty"`
}

// Confirm is RFC 7638/9449 `cnf`: the JWK SHA-256 thumbprint of the client's
// DPoP key.
type Confirm struct {
	JKT string `json:"jkt"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Signer issues tokens. Its zero value is unusable on purpose: a signer
// without a key must not exist.
type Signer struct {
	key *ecdsa.PrivateKey
	kid string
	iss string
	now func() time.Time
}

func NewSigner(iss, kid string, key *ecdsa.PrivateKey) (*Signer, error) {
	if key == nil {
		return nil, errors.New("tokens: signing key is required")
	}
	if iss == "" || kid == "" {
		return nil, errors.New("tokens: issuer and key id are required")
	}
	return &Signer{key: key, kid: kid, iss: iss, now: time.Now}, nil
}

// GenerateKey is a development convenience. Production keys come from the
// KMS/HSM path and never exist in this process.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Issue mints an access token. `ttl` is deliberately a parameter with no
// default: an access token lifetime is a decision, never an accident.
func (s *Signer) Issue(c Claims, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", errors.New("tokens: ttl must be positive")
	}
	now := s.now()
	c.Issuer = s.iss
	c.IssuedAt = now.Unix()
	c.NotBefore = now.Unix()
	c.ExpiresAt = now.Add(ttl).Unix()
	if c.JTI == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		c.JTI = base64.RawURLEncoding.EncodeToString(raw)
	}

	h, err := json.Marshal(header{Alg: "ES256", Typ: "at+jwt", Kid: s.kid})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)

	sum := sha256.Sum256([]byte(signing))
	r, sVal, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		return "", err
	}
	// JWS wants fixed-width R||S, not DER.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sVal.FillBytes(sig[32:])

	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verifier checks tokens. Expectations are supplied, never read from the
// token: an attacker controls every byte of the thing being verified.
type Verifier struct {
	key *ecdsa.PublicKey
	iss string
	now func() time.Time
	// Leeway absorbs modest clock skew between issuer and verifier.
	Leeway time.Duration
}

func NewVerifier(iss string, key *ecdsa.PublicKey) (*Verifier, error) {
	if key == nil || iss == "" {
		return nil, errors.New("tokens: issuer and public key are required")
	}
	return &Verifier{key: key, iss: iss, now: time.Now, Leeway: 30 * time.Second}, nil
}

// Verify checks signature first, then time, then issuer and audience. A
// token that fails any check yields no claims at all — there is no partial
// result a caller could mistake for a valid one.
func (v *Verifier) Verify(token, audience string) (*Claims, error) {
	var h header
	var c Claims

	parts := splitThree(token)
	if parts == nil {
		return nil, ErrMalformed
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &h) != nil {
		return nil, ErrMalformed
	}
	// The alg allowlist: `none` and RSA/HMAC confusion die here, before any
	// key is consulted.
	if h.Alg != "ES256" {
		return nil, ErrAlgorithm
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &c) != nil {
		return nil, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, ErrMalformed
	}

	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	sVal := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(v.key, sum[:], r, sVal) {
		return nil, ErrSignature
	}

	now := v.now()
	if now.After(time.Unix(c.ExpiresAt, 0).Add(v.Leeway)) {
		return nil, ErrExpired
	}
	if now.Before(time.Unix(c.NotBefore, 0).Add(-v.Leeway)) {
		return nil, ErrNotYet
	}
	if c.Issuer != v.iss {
		return nil, ErrIssuer
	}
	// Audience binding: a token minted for one resource server must not be
	// replayable at another.
	if audience != "" && c.Audience != audience {
		return nil, ErrAudience
	}
	return &c, nil
}

func splitThree(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
			if len(out) == 2 {
				break
			}
		}
	}
	if len(out) != 2 {
		return nil
	}
	out = append(out, s[start:])
	for _, p := range out {
		if p == "" {
			return nil
		}
	}
	return out
}

// Thumbprint is the RFC 7638 SHA-256 JWK thumbprint of a P-256 public key,
// used as the `cnf.jkt` value that binds a token to a DPoP key.
func Thumbprint(k *ecdsa.PublicKey) string {
	// Members must be lexicographic with no whitespace — the RFC's rules,
	// not a formatting preference: a different ordering is a different
	// thumbprint.
	x := base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, 32)))
	jwk := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y)
	sum := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
