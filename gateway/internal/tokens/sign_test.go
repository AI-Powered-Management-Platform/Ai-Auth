package tokens

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func pair(t *testing.T) (*Signer, *Verifier, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner("https://auth.example.com", "key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier("https://auth.example.com", &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return s, v, key
}

func claims() Claims {
	return Claims{Subject: "user-1", Audience: "api", TenantID: "t1", Scope: "openid"}
}

func TestARoundTripVerifies(t *testing.T) {
	s, v, _ := pair(t)
	tok, err := s.Issue(claims(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(tok, "api")
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "user-1" || got.TenantID != "t1" {
		t.Fatal("claims did not survive the round trip")
	}
}

func TestASignerWithoutAKeyCannotExist(t *testing.T) {
	if _, err := NewSigner("iss", "kid", nil); err == nil {
		t.Fatal("a signer without a key must not be constructible")
	}
}

func TestAnotherKeyCannotForgeAToken(t *testing.T) {
	s, _, _ := pair(t)
	_, otherV, _ := pair(t)
	tok, _ := s.Issue(claims(), time.Minute)
	if _, err := otherV.Verify(tok, "api"); !errors.Is(err, ErrSignature) {
		t.Fatal("a token must not verify under an unrelated key")
	}
}

func TestAlgNoneIsRefused(t *testing.T) {
	// The classic JWT attack: strip the signature, claim no algorithm.
	s, v, _ := pair(t)
	tok, _ := s.Issue(claims(), time.Minute)
	parts := strings.Split(tok, ".")

	hdr, _ := json.Marshal(map[string]string{"alg": "none", "typ": "at+jwt"})
	forged := base64.RawURLEncoding.EncodeToString(hdr) + "." + parts[1] + "." + parts[2]
	if _, err := v.Verify(forged, "api"); !errors.Is(err, ErrAlgorithm) {
		t.Fatal("alg:none must be refused before any key is consulted")
	}
}

func TestAlgConfusionIsRefused(t *testing.T) {
	s, v, _ := pair(t)
	tok, _ := s.Issue(claims(), time.Minute)
	parts := strings.Split(tok, ".")
	for _, alg := range []string{"HS256", "RS256", "ES384", ""} {
		hdr, _ := json.Marshal(map[string]string{"alg": alg, "typ": "at+jwt"})
		forged := base64.RawURLEncoding.EncodeToString(hdr) + "." + parts[1] + "." + parts[2]
		if _, err := v.Verify(forged, "api"); !errors.Is(err, ErrAlgorithm) {
			t.Fatalf("alg %q was not refused", alg)
		}
	}
}

func TestATamperedClaimBreaksTheSignature(t *testing.T) {
	s, v, _ := pair(t)
	tok, _ := s.Issue(claims(), time.Minute)
	parts := strings.Split(tok, ".")

	var c Claims
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(pb, &c)
	c.Subject = "admin" // privilege escalation attempt
	nb, _ := json.Marshal(c)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(nb) + "." + parts[2]

	if _, err := v.Verify(forged, "api"); !errors.Is(err, ErrSignature) {
		t.Fatal("an edited subject must break verification")
	}
}

func TestAnExpiredTokenIsRefused(t *testing.T) {
	s, v, _ := pair(t)
	base := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return base }
	tok, _ := s.Issue(claims(), time.Minute)
	v.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := v.Verify(tok, "api"); !errors.Is(err, ErrExpired) {
		t.Fatal("an expired token must be refused")
	}
}

func TestModestClockSkewIsTolerated(t *testing.T) {
	s, v, _ := pair(t)
	base := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return base }
	tok, _ := s.Issue(claims(), time.Minute)
	// Verifier's clock is 10s behind the issuer's.
	v.now = func() time.Time { return base.Add(-10 * time.Second) }
	if _, err := v.Verify(tok, "api"); err != nil {
		t.Fatalf("small skew must not break a fresh token: %v", err)
	}
}

func TestAWrongAudienceIsRefused(t *testing.T) {
	// A token minted for one resource server must not replay at another.
	s, v, _ := pair(t)
	tok, _ := s.Issue(claims(), time.Minute)
	if _, err := v.Verify(tok, "other-api"); !errors.Is(err, ErrAudience) {
		t.Fatal("audience binding must hold")
	}
}

func TestAWrongIssuerIsRefused(t *testing.T) {
	s, _, key := pair(t)
	other, err := NewVerifier("https://someone-else.example.com", &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := s.Issue(claims(), time.Minute)
	if _, err := other.Verify(tok, "api"); !errors.Is(err, ErrIssuer) {
		t.Fatal("issuer must be checked")
	}
}

func TestMalformedTokensAreRefusedNotPanicked(t *testing.T) {
	_, v, _ := pair(t)
	for _, bad := range []string{"", ".", "..", "a.b", "a.b.c.d", "a.b.", ".b.c", "not-a-token", "!!!.???.###"} {
		if _, err := v.Verify(bad, "api"); err == nil {
			t.Fatalf("malformed token %q was accepted", bad)
		}
	}
}

func TestATokenCarriesItsDPoPBinding(t *testing.T) {
	s, v, key := pair(t)
	c := claims()
	c.Confirm = &Confirm{JKT: Thumbprint(&key.PublicKey)}
	tok, _ := s.Issue(c, time.Minute)
	got, err := v.Verify(tok, "api")
	if err != nil {
		t.Fatal(err)
	}
	if got.Confirm == nil || got.Confirm.JKT != Thumbprint(&key.PublicKey) {
		t.Fatal("cnf.jkt must survive: it is what makes a stolen token useless")
	}
}

func TestThumbprintIsStableAndKeySpecific(t *testing.T) {
	_, _, k1 := pair(t)
	_, _, k2 := pair(t)
	if Thumbprint(&k1.PublicKey) != Thumbprint(&k1.PublicKey) {
		t.Fatal("thumbprint must be deterministic")
	}
	if Thumbprint(&k1.PublicKey) == Thumbprint(&k2.PublicKey) {
		t.Fatal("different keys must not share a thumbprint")
	}
}

func TestZeroTTLIsRefused(t *testing.T) {
	s, _, _ := pair(t)
	if _, err := s.Issue(claims(), 0); err == nil {
		t.Fatal("a token lifetime must be a decision, never an accident")
	}
}
