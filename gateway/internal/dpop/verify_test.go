package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	method = "POST"
	uri    = "https://auth.example.com/token"
)

type proofOpts struct {
	typ, alg, htm, htu, jti, ath string
	iat                          int64
	omitJWK                      bool
	leakPrivate                  bool
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// makeProof builds a real signed proof, so tests exercise the verifier
// rather than a fixture.
func makeProof(t *testing.T, key *ecdsa.PrivateKey, o proofOpts) string {
	t.Helper()
	if o.typ == "" {
		o.typ = "dpop+jwt"
	}
	if o.alg == "" {
		o.alg = "ES256"
	}
	if o.htm == "" {
		o.htm = method
	}
	if o.htu == "" {
		o.htu = uri
	}
	if o.jti == "" {
		o.jti = b64([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	if o.iat == 0 {
		o.iat = time.Now().Unix()
	}

	hdr := map[string]any{"typ": o.typ, "alg": o.alg}
	if !o.omitJWK {
		k := map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": b64(key.PublicKey.X.FillBytes(make([]byte, 32))),
			"y": b64(key.PublicKey.Y.FillBytes(make([]byte, 32))),
		}
		if o.leakPrivate {
			k["d"] = b64(key.D.FillBytes(make([]byte, 32)))
		}
		hdr["jwk"] = k
	}
	hb, _ := json.Marshal(hdr)

	pl := map[string]any{"jti": o.jti, "htm": o.htm, "htu": o.htu, "iat": o.iat}
	if o.ath != "" {
		pl["ath"] = o.ath
	}
	pb, _ := json.Marshal(pl)

	signing := b64(hb) + "." + b64(pb)
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

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func athFor(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64(sum[:])
}

func TestAGenuineProofVerifies(t *testing.T) {
	key := newKey(t)
	p, err := NewVerifier().Verify(makeProof(t, key, proofOpts{}), method, uri, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Thumbprint != Thumbprint(&key.PublicKey) {
		t.Fatal("thumbprint mismatch")
	}
}

func TestAStolenTokenWithoutTheKeyIsUseless(t *testing.T) {
	// The whole point of DPoP: the attacker has the token, not the key.
	victim, thief := newKey(t), newKey(t)
	token := "stolen.access.token"
	proof := makeProof(t, thief, proofOpts{ath: athFor(token)})

	_, err := NewVerifier().Verify(proof, method, uri, token, Thumbprint(&victim.PublicKey))
	if !errors.Is(err, ErrTokenBinding) {
		t.Fatalf("a stolen token must not be usable with another key, got %v", err)
	}
}

func TestAProofForAnotherTokenIsRefused(t *testing.T) {
	key := newKey(t)
	proof := makeProof(t, key, proofOpts{ath: athFor("token-a")})
	_, err := NewVerifier().Verify(proof, method, uri, "token-b", Thumbprint(&key.PublicKey))
	if !errors.Is(err, ErrTokenHash) {
		t.Fatalf("a proof captured for one token must not work with another, got %v", err)
	}
}

func TestReplayIsRefused(t *testing.T) {
	key := newKey(t)
	v := NewVerifier()
	proof := makeProof(t, key, proofOpts{jti: "fixed-jti"})
	if _, err := v.Verify(proof, method, uri, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(proof, method, uri, "", ""); !errors.Is(err, ErrReplay) {
		t.Fatalf("a captured proof must not replay, got %v", err)
	}
}

func TestAProofIsBoundToItsMethodAndURI(t *testing.T) {
	key := newKey(t)
	proof := makeProof(t, key, proofOpts{})
	v := NewVerifier()
	if _, err := v.Verify(proof, "GET", uri, "", ""); !errors.Is(err, ErrMethod) {
		t.Fatal("method binding must hold")
	}
	if _, err := v.Verify(proof, method, "https://auth.example.com/introspect", "", ""); !errors.Is(err, ErrURI) {
		t.Fatal("uri binding must hold")
	}
}

func TestQueryStringsDoNotBreakURIBinding(t *testing.T) {
	// RFC 9449 excludes query and fragment from htu.
	key := newKey(t)
	proof := makeProof(t, key, proofOpts{htu: uri})
	if _, err := NewVerifier().Verify(proof, method, uri+"?x=1#frag", "", ""); err != nil {
		t.Fatalf("query and fragment must not affect binding: %v", err)
	}
}

func TestASplicedProofFailsSignature(t *testing.T) {
	// Header claims the victim's key; payload and signature come from a
	// proof the thief made.
	victim, thief := newKey(t), newKey(t)
	gp := strings.SplitN(makeProof(t, victim, proofOpts{}), ".", 2)
	fp := strings.SplitN(makeProof(t, thief, proofOpts{}), ".", 2)
	spliced := gp[0] + "." + fp[1]
	if _, err := NewVerifier().Verify(spliced, method, uri, "", ""); !errors.Is(err, ErrSignature) {
		t.Fatal("a spliced proof must fail signature verification")
	}
}

func TestWrongTypeIsRefused(t *testing.T) {
	// Accepting another typ would let an access token be replayed as its own
	// proof.
	key := newKey(t)
	for _, typ := range []string{"jwt", "at+jwt", "JWT"} {
		proof := makeProof(t, key, proofOpts{typ: typ})
		if _, err := NewVerifier().Verify(proof, method, uri, "", ""); !errors.Is(err, ErrType) {
			t.Fatalf("typ %q accepted", typ)
		}
	}
}

func TestUnacceptableAlgorithmsAreRefused(t *testing.T) {
	key := newKey(t)
	for _, alg := range []string{"none", "HS256", "RS256", "ES384"} {
		proof := makeProof(t, key, proofOpts{alg: alg})
		if _, err := NewVerifier().Verify(proof, method, uri, "", ""); !errors.Is(err, ErrAlgorithm) {
			t.Fatalf("alg %q accepted", alg)
		}
	}
}

func TestAProofWithoutAKeyIsRefused(t *testing.T) {
	key := newKey(t)
	proof := makeProof(t, key, proofOpts{omitJWK: true})
	if _, err := NewVerifier().Verify(proof, method, uri, "", ""); !errors.Is(err, ErrKeyMissing) {
		t.Fatal("a proof must carry its public key")
	}
}

func TestAProofLeakingAPrivateKeyIsRefused(t *testing.T) {
	key := newKey(t)
	proof := makeProof(t, key, proofOpts{leakPrivate: true})
	if _, err := NewVerifier().Verify(proof, method, uri, "", ""); !errors.Is(err, ErrKeyInvalid) {
		t.Fatal("a private key in the header must be refused loudly")
	}
}

func TestStaleAndFutureProofsAreRefused(t *testing.T) {
	key := newKey(t)
	old := makeProof(t, key, proofOpts{iat: time.Now().Add(-5 * time.Minute).Unix()})
	if _, err := NewVerifier().Verify(old, method, uri, "", ""); !errors.Is(err, ErrStale) {
		t.Fatal("an old proof must be refused")
	}
	future := makeProof(t, key, proofOpts{iat: time.Now().Add(5 * time.Minute).Unix()})
	if _, err := NewVerifier().Verify(future, method, uri, "", ""); !errors.Is(err, ErrStale) {
		t.Fatal("a future-dated proof must be refused")
	}
}

func TestAFailedProofDoesNotConsumeItsJTI(t *testing.T) {
	// Otherwise an attacker could burn a legitimate client's identifiers by
	// submitting broken proofs that carry them.
	key := newKey(t)
	v := NewVerifier()
	bad := makeProof(t, key, proofOpts{jti: "shared-jti", htm: "PUT"})
	if _, err := v.Verify(bad, method, uri, "", ""); !errors.Is(err, ErrMethod) {
		t.Fatal("setup: expected a method failure")
	}
	good := makeProof(t, key, proofOpts{jti: "shared-jti"})
	if _, err := v.Verify(good, method, uri, "", ""); err != nil {
		t.Fatalf("a failed proof must not burn the jti: %v", err)
	}
}

func TestMalformedProofsAreRefusedNotPanicked(t *testing.T) {
	v := NewVerifier()
	for _, bad := range []string{"", ".", "..", "a.b", "a.b.c.d", "!!!.???.###", "a..c"} {
		if _, err := v.Verify(bad, method, uri, "", ""); err == nil {
			t.Fatalf("malformed proof %q accepted", bad)
		}
	}
}

func TestAKeyOffTheCurveIsRefused(t *testing.T) {
	raw := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"` +
		b64(make([]byte, 32)) + `","y":"` + b64(make([]byte, 32)) + `"}`)
	if _, err := parseJWK(raw); !errors.Is(err, ErrKeyInvalid) {
		t.Fatal("a point off the curve must be refused")
	}
}
