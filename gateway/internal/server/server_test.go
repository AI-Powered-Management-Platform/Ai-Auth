package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestHealthzAlwaysOK(t *testing.T) {
	if rec := get(t, New(Config{Version: "test"}), "/healthz"); rec.Code != http.StatusOK {
		t.Fatalf("healthz: got %d", rec.Code)
	}
}

func TestReadyzWithoutGuardIsReady(t *testing.T) {
	if rec := get(t, New(Config{Version: "test"}), "/readyz"); rec.Code != http.StatusOK {
		t.Fatalf("readyz (no guard): got %d", rec.Code)
	}
}

func TestReadyzHealthyGuard(t *testing.T) {
	h := New(Config{Version: "test", Guard: func(context.Context) error { return nil }})
	if rec := get(t, h, "/readyz"); rec.Code != http.StatusOK {
		t.Fatalf("readyz (healthy): got %d", rec.Code)
	}
}

func TestReadyzFailsClosedWhenGuardUnreachable(t *testing.T) {
	h := New(Config{Version: "test", Guard: func(context.Context) error { return errors.New("no route to guard") }})
	rec := get(t, h, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz must be 503 when the Guard cannot answer, got %d", rec.Code)
	}
}

func TestUnknownPathIs404(t *testing.T) {
	if rec := get(t, New(Config{Version: "test"}), "/nope"); rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
}
