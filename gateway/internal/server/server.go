// Package server holds the gateway's HTTP surface. v1 skeleton: health only.
// Every future handler lives behind the same mux so timeouts, logging, and
// security headers attach in exactly one place.
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// GuardCheck reports whether the crypto service answers on its mTLS channel.
// nil means "no Guard configured" (bare skeleton mode).
type GuardCheck func(context.Context) error

// New returns the gateway mux. /healthz says the process is up. /readyz is
// the fail-closed door: if the Guard cannot answer, this instance must not
// receive authentication traffic — no Guard means nobody gets in, so a
// not-ready gateway is the correct shape of that rule at the LB layer.
func New(version string, guard GuardCheck) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": version})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if guard == nil {
			writeJSON(w, http.StatusOK, map[string]string{
				"status": "ready", "guard": "not configured", "version": version,
			})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()
		if err := guard(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not ready", "guard": err.Error(), "version": version,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ready", "guard": "ok", "version": version,
		})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
