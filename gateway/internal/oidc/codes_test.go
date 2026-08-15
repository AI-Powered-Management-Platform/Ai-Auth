package oidc

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func testGrant() Grant {
	return Grant{
		ClientID:      "app",
		RedirectURI:   registered,
		Scope:         "openid",
		CodeChallenge: "challenge",
		SubjectID:     "user-1",
		TenantID:      "tenant-1",
	}
}

// storeAt returns a store whose clock the test controls.
func storeAt(start time.Time) (*CodeStore, *time.Time) {
	now := start
	s := NewCodeStore()
	s.now = func() time.Time { return now }
	return s, &now
}

func TestACodeRedeemsOnce(t *testing.T) {
	s := NewCodeStore()
	code, err := s.Issue(testGrant())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(code, "app", registered); err != nil {
		t.Fatalf("first redemption must succeed: %v", err)
	}
	if _, err := s.Redeem(code, "app", registered); !errors.Is(err, ErrCodeUnknown) {
		t.Fatal("a code must never be redeemable twice")
	}
}

func TestRedeemReturnsTheGrant(t *testing.T) {
	s := NewCodeStore()
	code, _ := s.Issue(testGrant())
	g, err := s.Redeem(code, "app", registered)
	if err != nil {
		t.Fatal(err)
	}
	if g.SubjectID != "user-1" || g.TenantID != "tenant-1" || g.CodeChallenge != "challenge" {
		t.Fatal("the grant lost fields the token endpoint needs")
	}
}

func TestAnotherClientCannotRedeem(t *testing.T) {
	s := NewCodeStore()
	code, _ := s.Issue(testGrant())
	if _, err := s.Redeem(code, "different-app", registered); !errors.Is(err, ErrCodeClient) {
		t.Fatal("a code must be bound to the client it was issued to")
	}
}

func TestADifferentRedirectCannotRedeem(t *testing.T) {
	s := NewCodeStore()
	code, _ := s.Issue(testGrant())
	if _, err := s.Redeem(code, "app", "https://evil.com/callback"); !errors.Is(err, ErrCodeRedirect) {
		t.Fatal("redemption must require the same redirect used at authorization")
	}
}

func TestAFailedRedemptionStillBurnsTheCode(t *testing.T) {
	// An attacker holding a stolen code gets one attempt, not an oracle.
	s := NewCodeStore()
	code, _ := s.Issue(testGrant())
	if _, err := s.Redeem(code, "wrong-client", registered); err == nil {
		t.Fatal("expected refusal")
	}
	if _, err := s.Redeem(code, "app", registered); !errors.Is(err, ErrCodeUnknown) {
		t.Fatal("a failed attempt must consume the code")
	}
}

func TestAnExpiredCodeIsRefused(t *testing.T) {
	s, now := storeAt(time.Unix(1_700_000_000, 0))
	code, _ := s.Issue(testGrant())
	*now = now.Add(CodeTTL + time.Second)
	if _, err := s.Redeem(code, "app", registered); !errors.Is(err, ErrCodeUnknown) {
		t.Fatal("an expired code must not redeem")
	}
}

func TestACodeJustInsideTheWindowStillWorks(t *testing.T) {
	s, now := storeAt(time.Unix(1_700_000_000, 0))
	code, _ := s.Issue(testGrant())
	*now = now.Add(CodeTTL - time.Second)
	if _, err := s.Redeem(code, "app", registered); err != nil {
		t.Fatalf("a code inside its window must redeem: %v", err)
	}
}

func TestExpiredCodesAreEvicted(t *testing.T) {
	s, now := storeAt(time.Unix(1_700_000_000, 0))
	for i := 0; i < 50; i++ {
		if _, err := s.Issue(testGrant()); err != nil {
			t.Fatal(err)
		}
	}
	*now = now.Add(CodeTTL + time.Second)
	if _, err := s.Issue(testGrant()); err != nil { // triggers eviction
		t.Fatal(err)
	}
	if n := s.Len(); n != 1 {
		t.Fatalf("expired codes must not accumulate: %d remain", n)
	}
}

func TestCodesAreUnique(t *testing.T) {
	s := NewCodeStore()
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		code, err := s.Issue(testGrant())
		if err != nil {
			t.Fatal(err)
		}
		if seen[code] {
			t.Fatal("code collision: issuance must be unpredictable and unique")
		}
		seen[code] = true
	}
}

func TestConcurrentRedemptionYieldsExactlyOneWinner(t *testing.T) {
	// The race that matters: two requests presenting the same stolen code.
	s := NewCodeStore()
	code, _ := s.Issue(testGrant())

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Redeem(code, "app", registered); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one redemption may succeed, got %d", wins)
	}
}
