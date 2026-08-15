package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func handler() (*Authorize, *PendingStore) {
	p := NewPendingStore()
	return &Authorize{Clients: testLookup, Pending: p, LoginURL: "/login"}, p
}

func authorizeGet(t *testing.T, h *Authorize, params url.Values) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))
	return rec
}

func TestAValidRequestRedirectsToLogin(t *testing.T) {
	h, pending := handler()
	rec := authorizeGet(t, h, valid())

	if rec.Code != http.StatusFound {
		t.Fatalf("got %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != "/login" {
		t.Fatalf("sent to %q, want /login", loc.Path)
	}
	if loc.Query().Get("rid") == "" {
		t.Fatal("the pending id must travel to the login step")
	}
	if pending.Len() != 1 {
		t.Fatal("the validated request must be held server-side")
	}
}

func TestOnlyTheOpaqueIdTravelsToTheBrowser(t *testing.T) {
	// The request's parameters must not round-trip through the client, or
	// the user's browser could alter what was requested.
	h, _ := handler()
	rec := authorizeGet(t, h, valid())
	loc := rec.Header().Get("Location")

	for _, leaked := range []string{"redirect_uri", "code_challenge", "client_id", "scope"} {
		if strings.Contains(loc, leaked) {
			t.Fatalf("%q leaked into the login redirect: %s", leaked, loc)
		}
	}
}

func TestAnUnknownClientIsShownNotRedirected(t *testing.T) {
	h, _ := handler()
	p := valid()
	p.Set("client_id", "nobody")
	rec := authorizeGet(t, h, p)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("an unknown client must never produce a redirect")
	}
}

func TestAnUnmatchedRedirectIsNeverFollowed(t *testing.T) {
	// The open-redirector case: the attacker supplies the destination and a
	// broken request as the excuse to visit it.
	h, _ := handler()
	p := valid()
	p.Set("redirect_uri", "https://evil.com/steal")
	p.Set("response_type", "token")
	rec := authorizeGet(t, h, p)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("refused request produced a redirect to %q", loc)
	}
}

func TestARecoverableErrorRedirectsWithStatePreserved(t *testing.T) {
	h, _ := handler()
	p := valid()
	p.Del("code_challenge") // valid client and redirect, bad request
	rec := authorizeGet(t, h, p)

	if rec.Code != http.StatusFound {
		t.Fatalf("got %d, want 302", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Host != "app.example.com" {
		t.Fatalf("error went to %q", loc.Host)
	}
	if loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("error code = %q", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "xyz" {
		t.Fatal("state must survive an error redirect")
	}
}

func TestUnsupportedResponseTypeUsesItsOwnErrorCode(t *testing.T) {
	h, _ := handler()
	p := valid()
	p.Set("response_type", "token")
	rec := authorizeGet(t, h, p)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "unsupported_response_type" {
		t.Fatalf("error code = %q", loc.Query().Get("error"))
	}
}

func TestResponsesAreNotCached(t *testing.T) {
	h, _ := handler()
	if got := authorizeGet(t, h, valid()).Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestAPendingRequestIsSingleUse(t *testing.T) {
	p := NewPendingStore()
	id, err := p.Put(AuthzRequest{ClientID: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Take(id); !ok {
		t.Fatal("first take must succeed")
	}
	if _, ok := p.Take(id); ok {
		t.Fatal("a login ceremony completes once")
	}
}

func TestAnExpiredPendingRequestIsRefused(t *testing.T) {
	p := NewPendingStore()
	now := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return now }
	id, _ := p.Put(AuthzRequest{ClientID: "app"})
	now = now.Add(PendingTTL + time.Second)
	if _, ok := p.Take(id); ok {
		t.Fatal("an abandoned login must not stay usable")
	}
}
