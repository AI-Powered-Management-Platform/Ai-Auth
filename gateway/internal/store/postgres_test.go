package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests need a real Postgres: the properties under test — atomic
// single-use, cross-replica visibility — are database behaviour, and a fake
// would test the fake.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping database integration tests")
	}
	pool, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func seed(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO control.tenants (id, name) VALUES ('t1','Test')
		 ON CONFLICT (id) DO NOTHING`,
		`INSERT INTO gateway.subjects (tenant_id, id) VALUES ('t1','u1')
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func testGrant() Grant {
	return Grant{
		ClientID: "app", RedirectURI: "https://app.example.com/cb",
		Scope: "openid", CodeChallenge: "chal",
		SubjectID: "u1", TenantID: "t1", AuthTime: time.Now(),
	}
}

func uniqueCode(t *testing.T, suffix string) string {
	t.Helper()
	return t.Name() + "-" + suffix
}

func TestACodeRedeemsOnce(t *testing.T) {
	pool := testPool(t)
	seed(t, pool)
	c := NewCodes(pool)
	ctx := context.Background()
	code := uniqueCode(t, "1")

	if err := c.Insert(ctx, code, testGrant(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	g, err := c.Redeem(ctx, code, "app", "https://app.example.com/cb")
	if err != nil {
		t.Fatal(err)
	}
	if g.SubjectID != "u1" || g.CodeChallenge != "chal" {
		t.Fatal("grant lost fields the token endpoint needs")
	}
	if _, err := c.Redeem(ctx, code, "app", "https://app.example.com/cb"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a code must never redeem twice")
	}
}

func TestConcurrentRedemptionHasExactlyOneWinner(t *testing.T) {
	// The property that in-memory locking cannot provide across replicas.
	pool := testPool(t)
	seed(t, pool)
	c := NewCodes(pool)
	ctx := context.Background()
	code := uniqueCode(t, "race")

	if err := c.Insert(ctx, code, testGrant(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Redeem(ctx, code, "app", "https://app.example.com/cb"); err == nil {
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

func TestAFailedRedemptionStillBurnsTheCode(t *testing.T) {
	pool := testPool(t)
	seed(t, pool)
	c := NewCodes(pool)
	ctx := context.Background()
	code := uniqueCode(t, "burn")

	if err := c.Insert(ctx, code, testGrant(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Redeem(ctx, code, "wrong-client", "https://app.example.com/cb"); err == nil {
		t.Fatal("expected refusal")
	}
	if _, err := c.Redeem(ctx, code, "app", "https://app.example.com/cb"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a wrong client must consume the code, not allow a retry")
	}
}

func TestAnExpiredCodeIsRefused(t *testing.T) {
	pool := testPool(t)
	seed(t, pool)
	c := NewCodes(pool)
	ctx := context.Background()
	code := uniqueCode(t, "expired")

	if err := c.Insert(ctx, code, testGrant(), time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Redeem(ctx, code, "app", "https://app.example.com/cb"); !errors.Is(err, ErrNotFound) {
		t.Fatal("an expired code must not redeem")
	}
}

func TestRevocationSurvivesAcrossConnections(t *testing.T) {
	// The point of moving this to Postgres: a restart must not resurrect a
	// killed session.
	pool := testPool(t)
	seed(t, pool)
	ctx := context.Background()
	r := NewRevocations(pool)

	issued := time.Now().Add(-time.Minute)
	if err := r.RevokeSubject(ctx, "t1", "u1"); err != nil {
		t.Fatal(err)
	}

	// A second pool stands in for another replica, or the same process after
	// a restart.
	other := NewRevocations(testPool(t))
	revoked, err := other.IsRevoked(ctx, "some-jti", "t1", "u1", issued)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("a revocation must be visible to every replica")
	}
}

func TestALaterLoginIsNotCaughtByAnEarlierCutoff(t *testing.T) {
	pool := testPool(t)
	seed(t, pool)
	ctx := context.Background()
	r := NewRevocations(pool)

	if err := r.RevokeSubject(ctx, "t1", "u1"); err != nil {
		t.Fatal(err)
	}
	fresh := time.Now().Add(time.Minute)
	revoked, err := r.IsRevoked(ctx, "j", "t1", "u1", fresh)
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("a token issued after the cutoff must be accepted")
	}
}

func TestTenantRevocationReachesEveryone(t *testing.T) {
	pool := testPool(t)
	seed(t, pool)
	ctx := context.Background()
	r := NewRevocations(pool)
	issued := time.Now().Add(-time.Minute)

	if err := r.RevokeTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"u1", "u2", "someone-else"} {
		revoked, err := r.IsRevoked(ctx, "j", "t1", sub, issued)
		if err != nil {
			t.Fatal(err)
		}
		if !revoked {
			t.Fatalf("tenant revocation missed subject %q", sub)
		}
	}
}

func TestATokenRevocationIsScopedToItsJTI(t *testing.T) {
	pool := testPool(t)
	seed(t, pool)
	ctx := context.Background()
	r := NewRevocations(pool)
	jti := uniqueCode(t, "jti")

	if err := r.RevokeToken(ctx, jti, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	dead, err := r.IsRevoked(ctx, jti, "t1", "u1", time.Now())
	if err != nil || !dead {
		t.Fatal("the revoked token must be refused")
	}
	alive, err := r.IsRevoked(ctx, jti+"-other", "t1", "u1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if alive {
		t.Fatal("another token of the same user must keep working")
	}
}
