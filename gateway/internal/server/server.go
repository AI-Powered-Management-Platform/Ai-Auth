// Package server holds the gateway's HTTP surface. v1 skeleton: health only.
// Every future handler lives behind the same mux so timeouts, logging, and
// security headers attach in exactly one place.
package server

import (
	"encoding/json"
	"net/http"
)

// New returns the gateway mux. Health endpoints only, for now: /healthz says
// the process is up; /readyz will later also require Postgres, Redis, and the
// Guard's mTLS channel — per the fail-closed matrix, not-ready means reject.
func New(version string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "version": version})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		// Skeleton: no dependencies wired yet, so readiness equals liveness.
		writeJSON(w, map[string]string{"status": "ready", "version": version})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
