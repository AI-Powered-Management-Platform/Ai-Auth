// Package dpop verifies DPoP proofs (RFC 9449).
//
// A DPoP proof is a JWT the client signs with a private key it holds. The
// access token carries `cnf.jkt`, the thumbprint of the matching public key.
// Together they turn a bearer token into a sender-constrained one: whoever
// steals the token still cannot produce a proof, because the private key
// never left the client's hardware.
//
// This is the answer to threat-model T1 — session theft after login. Passkeys
// protect the login moment; this protects everything after it.
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrMalformed    = errors.New("dpop proof is malformed")
	ErrType         = errors.New("dpop proof has the wrong typ")
	ErrAlgorithm    = errors.New("dpop proof uses an unacceptable algorithm")
	ErrKeyMissing   = errors.New("dpop proof carries no public key")
	ErrKeyInvalid   = errors.New("dpop proof carries an unusable public key")
	ErrSignature    = errors.New("dpop proof signature does not verify")
	ErrMethod       = errors.New("dpop proof is not bound to this method")
	ErrURI          = errors.New("dpop proof is not bound to this URI")
	ErrStale        = errors.New("dpop proof is outside its freshness window")
	ErrReplay       = errors.New("dpop proof has already been used")
	ErrTokenBinding = errors.New("dpop key does not match the token's confirmation")
	ErrTokenHash    = errors.New("dpop proof is not bound to this access token")
)

// MaxAge bounds how old a proof may be. Short, because the window is exactly
// how long a captured proof stays replayable against a server that has lost
// its jti cache.
const MaxAge = 60 * time.Second

type header struct {
	Typ string          `json:"typ"`
	Alg string          `json:"alg"`
	JWK json.RawMessage `json:"jwk"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	// A private key must never appear in a proof header. Its presence means
	// the client is leaking, so we refuse rather than quietly accept.
	D string `json:"d"`
}

type payload struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath"`
}

// Proof is what a verified DPoP proof establishes.
type Proof struct {
	// Thumbprint is the RFC 7638 JWK thumbprint of the proving key. An
	// access token is bound to this value through its cnf.jkt claim.
	Thumbprint string
	JTI        string
}

// Verifier checks proofs. It holds the replay cache, so one instance must be
// shared across handlers — a per-request verifier would remember nothing.
type Verifier struct {
	seen *replayCache
	now  func() time.Time
}

func NewVerifier() *Verifier {
	return &Verifier{seen: newReplayCache(), now: time.Now}
}

// Verify checks a proof against the request it claims to be bound to.
//
// accessToken may be empty at the token endpoint, where no access token
// exists yet. When present, both the token hash and the key binding are
// checked — either one alone would leave a gap.
func (v *Verifier) Verify(proofJWT, method, uri, accessToken, tokenJKT string) (*Proof, error) {
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, ErrMalformed
	}

	var h header
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &h) != nil {
		return nil, ErrMalformed
	}
	// typ is checked before anything else: a proof is a distinct token type,
	// and accepting another type here would let an access token or an id
	// token be replayed as its own proof.
	if h.Typ != "dpop+jwt" {
		return nil, ErrType
	}
	if h.Alg != "ES256" {
		return nil, ErrAlgorithm
	}
	if len(h.JWK) == 0 {
		return nil, ErrKeyMissing
	}

	pub, err := parseJWK(h.JWK)
	if err != nil {
		return nil, err
	}

	var p payload
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &p) != nil {
		return nil, ErrMalformed
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, ErrMalformed
	}

	// The proof is self-signed by the key it carries, so this proves only
	// possession of that key. Binding it to an identity is the cnf.jkt check
	// further down — the two together are what matter.
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return nil, ErrSignature
	}

	if !strings.EqualFold(p.HTM, method) {
		return nil, ErrMethod
	}
	if !sameURI(p.HTU, uri) {
		return nil, ErrURI
	}

	now := v.now()
	age := now.Sub(time.Unix(p.IAT, 0))
	if age > MaxAge || age < -MaxAge {
		return nil, ErrStale
	}

	thumb := Thumbprint(pub)

	if accessToken != "" {
		// ath binds the proof to one specific token, so a proof captured on
		// one call cannot be reused with a different token.
		want := sha256.Sum256([]byte(accessToken))
		wantB64 := base64.RawURLEncoding.EncodeToString(want[:])
		if subtle.ConstantTimeCompare([]byte(p.ATH), []byte(wantB64)) != 1 {
			return nil, ErrTokenHash
		}
		// And this is the binding that makes a stolen token worthless: the
		// token names a key, and the proof must be signed by that key.
		if subtle.ConstantTimeCompare([]byte(thumb), []byte(tokenJKT)) != 1 {
			return nil, ErrTokenBinding
		}
	}

	// Replay check last: a proof that fails any check above must not consume
	// a jti, or an attacker could burn a legitimate client's identifiers.
	if p.JTI == "" {
		return nil, ErrMalformed
	}
	if !v.seen.admit(p.JTI, now.Add(2*MaxAge)) {
		return nil, ErrReplay
	}

	return &Proof{Thumbprint: thumb, JTI: p.JTI}, nil
}

func parseJWK(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	var k jwk
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, ErrKeyInvalid
	}
	if k.D != "" {
		// A private key in a proof header is a client bug with severe
		// consequences; refusing makes it loud instead of silent.
		return nil, ErrKeyInvalid
	}
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, ErrKeyInvalid
	}
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, ErrKeyInvalid
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	// A point off the curve can produce nonsense verification results.
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, ErrKeyInvalid
	}
	return pub, nil
}

// sameURI compares htu to the request URI. RFC 9449 excludes query and
// fragment, so a proof stays valid across the same endpoint with different
// parameters.
func sameURI(htu, actual string) bool {
	a, err1 := url.Parse(htu)
	b, err2 := url.Parse(actual)
	if err1 != nil || err2 != nil {
		return false
	}
	a.RawQuery, a.Fragment = "", ""
	b.RawQuery, b.Fragment = "", ""
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Host, b.Host) &&
		a.Path == b.Path
}

// Thumbprint is the RFC 7638 SHA-256 JWK thumbprint of a P-256 key. Members
// must be lexicographic with no whitespace: a different ordering is a
// different thumbprint, not a formatting choice.
func Thumbprint(k *ecdsa.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, 32)))
	jwkJSON := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	sum := sha256.Sum256([]byte(jwkJSON))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// replayCache remembers jti values for as long as a proof could still be
// fresh. Bounded, because an attacker choosing jti values would otherwise
// grow it without limit.
type replayCache struct {
	mu    sync.Mutex
	items map[string]time.Time
	max   int
	now   func() time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{items: make(map[string]time.Time), max: 100_000, now: time.Now}
}

// admit records a jti and reports whether it was new.
func (c *replayCache) admit(jti string, until time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, seen := c.items[jti]; seen {
		return false
	}
	if len(c.items) >= c.max {
		now := c.now()
		for k, exp := range c.items {
			if now.After(exp) {
				delete(c.items, k)
			}
		}
		// Still full means the cache is under attack rather than merely
		// busy. Refusing is the safe direction: a legitimate client retries,
		// and an attacker gains nothing.
		if len(c.items) >= c.max {
			return false
		}
	}
	c.items[jti] = until
	return true
}
