package sessions

import (
	"testing"
	"time"
)

func TestAnUnrevokedTokenPasses(t *testing.T) {
	r := NewRevocations()
	if r.IsRevoked("jti-1", "t1", "u1", time.Now()) {
		t.Fatal("nothing was revoked")
	}
}

func TestRevokingOneTokenLeavesOthersAlone(t *testing.T) {
	r := NewRevocations()
	r.RevokeToken("jti-1", time.Now().Add(time.Hour))
	if !r.IsRevoked("jti-1", "t1", "u1", time.Now()) {
		t.Fatal("the revoked token must be refused")
	}
	if r.IsRevoked("jti-2", "t1", "u1", time.Now()) {
		t.Fatal("another token of the same user must keep working")
	}
}

func TestRevokingASubjectKillsEveryTokenTheyHold(t *testing.T) {
	r := NewRevocations()
	issued := time.Now().Add(-time.Minute)
	r.RevokeSubject("t1", "u1")

	for _, jti := range []string{"a", "b", "c"} {
		if !r.IsRevoked(jti, "t1", "u1", issued) {
			t.Fatalf("token %q survived a subject revocation", jti)
		}
	}
	if r.IsRevoked("d", "t1", "other-user", issued) {
		t.Fatal("another user must be unaffected")
	}
}

func TestALaterLoginIsNotCaughtByAnEarlierCutoff(t *testing.T) {
	// Revocation is an instant, not a ban: signing in again must work.
	r := NewRevocations()
	r.RevokeSubject("t1", "u1")
	fresh := time.Now().Add(time.Second)
	if r.IsRevoked("new-jti", "t1", "u1", fresh) {
		t.Fatal("a token issued after the cutoff must be accepted")
	}
}

func TestATokenIssuedExactlyAtTheCutoffIsRevoked(t *testing.T) {
	// The boundary must fall closed: an ambiguous instant is a denial.
	r := NewRevocations()
	at := time.Unix(1_700_000_000, 0)
	r.now = func() time.Time { return at }
	r.RevokeSubject("t1", "u1")
	if !r.IsRevoked("j", "t1", "u1", at) {
		t.Fatal("a token issued at the cutoff instant must be revoked")
	}
}

func TestRevokingATenantKillsEveryone(t *testing.T) {
	r := NewRevocations()
	issued := time.Now().Add(-time.Minute)
	r.RevokeTenant("t1")
	if !r.IsRevoked("a", "t1", "u1", issued) || !r.IsRevoked("b", "t1", "u2", issued) {
		t.Fatal("a tenant revocation must reach every user in it")
	}
	if r.IsRevoked("c", "t2", "u1", issued) {
		t.Fatal("another tenant must be unaffected")
	}
}

func TestSubjectCutoffsAreScopedToTheirTenant(t *testing.T) {
	// The same subject id in two tenants must not be conflated.
	r := NewRevocations()
	issued := time.Now().Add(-time.Minute)
	r.RevokeSubject("t1", "shared-id")
	if r.IsRevoked("j", "t2", "shared-id", issued) {
		t.Fatal("revocation leaked across a tenant boundary")
	}
}

func TestExpiredTokenEntriesAreForgotten(t *testing.T) {
	r := NewRevocations()
	now := time.Unix(1_700_000_000, 0)
	r.now = func() time.Time { return now }
	for _, jti := range []string{"a", "b", "c"} {
		r.RevokeToken(jti, now.Add(time.Minute))
	}
	now = now.Add(time.Hour)
	r.RevokeToken("d", now.Add(time.Minute)) // triggers the sweep

	tok, _, _ := r.Len()
	if tok != 1 {
		t.Fatalf("expired entries should be dropped, %d remain", tok)
	}
}

func TestSubjectCutoffsAreNeverSwept(t *testing.T) {
	// Dropping one would resurrect every token it was killing.
	r := NewRevocations()
	now := time.Unix(1_700_000_000, 0)
	r.now = func() time.Time { return now }
	r.RevokeSubject("t1", "u1")
	now = now.Add(30 * 24 * time.Hour)
	r.RevokeToken("x", now.Add(time.Minute))

	if !r.IsRevoked("old", "t1", "u1", time.Unix(1_700_000_000, 0)) {
		t.Fatal("a subject cutoff must outlive any sweep")
	}
}
