package oidc

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestRegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Client{ID: "app", RedirectURIs: []string{registered}}); err != nil {
		t.Fatal(err)
	}
	c, ok := r.Lookup("app")
	if !ok || c.ID != "app" {
		t.Fatal("registered client not found")
	}
	if _, ok := r.Lookup("other"); ok {
		t.Fatal("unregistered client was found")
	}
}

func TestReRegistrationIsRefused(t *testing.T) {
	// Silent overwrite would let a replayed admin request retarget an
	// existing client's redirects.
	r := NewRegistry()
	c := Client{ID: "app", RedirectURIs: []string{registered}}
	if err := r.Register(c); err != nil {
		t.Fatal(err)
	}
	evil := Client{ID: "app", RedirectURIs: []string{"https://evil.com/cb"}}
	if err := r.Register(evil); !errors.Is(err, ErrClientExists) {
		t.Fatal("re-registration must be refused")
	}
	got, _ := r.Lookup("app")
	if got.RedirectURIs[0] != registered {
		t.Fatal("the original redirect must survive a rejected re-registration")
	}
}

func TestRegisteredRedirectsCannotBeMutatedLater(t *testing.T) {
	r := NewRegistry()
	uris := []string{registered}
	if err := r.Register(Client{ID: "app", RedirectURIs: uris}); err != nil {
		t.Fatal(err)
	}
	uris[0] = "https://evil.com/cb" // caller mutates its own slice
	got, _ := r.Lookup("app")
	if got.RedirectURIs[0] != registered {
		t.Fatal("the registry must hold its own copy")
	}
}

func TestWildcardRedirectsAreRefused(t *testing.T) {
	// Matching is exact, so a stored wildcard is either a mistake or an
	// attempt to widen the target set.
	r := NewRegistry()
	for _, bad := range []string{
		"https://*.example.com/cb",
		"https://app.example.com/*",
		"https://app.example.com/cb?x=*",
		"https://app.example.com/?",
	} {
		if err := r.Register(Client{ID: "c", RedirectURIs: []string{bad}}); !errors.Is(err, ErrBadRedirect) {
			t.Fatalf("wildcard %q was accepted", bad)
		}
	}
}

func TestPlainHTTPIsRefusedExceptLoopback(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Client{ID: "a", RedirectURIs: []string{"http://app.example.com/cb"}}); !errors.Is(err, ErrBadRedirect) {
		t.Fatal("plain http leaks the code to the network and must be refused")
	}
	// RFC 8252 §7.3: loopback is the documented native-app exception.
	for _, ok := range []string{"http://127.0.0.1:8080/cb", "http://localhost:1234/cb", "http://[::1]:9/cb"} {
		if err := r.Register(Client{ID: ok, RedirectURIs: []string{ok}}); err != nil {
			t.Fatalf("loopback %q refused: %v", ok, err)
		}
	}
}

func TestFragmentsAreRefused(t *testing.T) {
	// A fragment never reaches the server, so a registered one can never
	// match — storing it guarantees a broken client.
	r := NewRegistry()
	if err := r.Register(Client{ID: "a", RedirectURIs: []string{"https://app.example.com/cb#frag"}}); !errors.Is(err, ErrBadRedirect) {
		t.Fatal("fragment was accepted")
	}
}

func TestRelativeAndMalformedRedirectsAreRefused(t *testing.T) {
	r := NewRegistry()
	for _, bad := range []string{"/callback", "app.example.com/cb", "", "://nope"} {
		if err := r.Register(Client{ID: "a", RedirectURIs: []string{bad}}); err == nil {
			t.Fatalf("redirect %q was accepted", bad)
		}
	}
}

func TestCustomSchemesAreAllowedForNativeApps(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Client{ID: "native", RedirectURIs: []string{"com.example.app://callback"}}); err != nil {
		t.Fatalf("custom scheme refused: %v", err)
	}
}

func TestAClientNeedsAtLeastOneRedirect(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Client{ID: "app"}); !errors.Is(err, ErrNoRedirectURI) {
		t.Fatal("a client with no redirect must be refused")
	}
}

func TestRegistryFeedsValidateAuthzDirectly(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Client{ID: "app", RedirectURIs: []string{registered}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAuthz(valid(), r.Lookup); err != nil {
		t.Fatalf("a registered client should authorize: %v", err)
	}
	// And a near-miss redirect still fails, since matching stays exact.
	p := valid()
	p.Set("redirect_uri", registered+"/")
	if _, err := ValidateAuthz(p, r.Lookup); !errors.Is(err, ErrRedirectMismatch) {
		t.Fatal("exact matching must survive registration")
	}
}

func TestConcurrentReadsAndWritesAreSafe(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "client-" + strings.Repeat("x", i%5)
			_ = r.Register(Client{ID: id, RedirectURIs: []string{registered}})
			r.Lookup(id)
		}(i)
	}
	wg.Wait()
}
