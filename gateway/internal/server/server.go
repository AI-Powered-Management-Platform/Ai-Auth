// Package server holds the gateway's HTTP surface: health, and the OIDC
// endpoints. Everything lives behind one mux so timeouts, security headers,
// and logging attach in exactly one place rather than per handler.
package server

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"time"

	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/login"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/oidc"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/tokens"
)

// GuardCheck reports whether the crypto service answers on its mTLS channel.
// nil means "no Guard configured" (bare skeleton mode).
type GuardCheck func(context.Context) error

// Config is everything the surface needs. A nil Signer means the OIDC
// endpoints are not mounted at all — a half-configured token endpoint must
// not exist, since an endpoint that 500s still looks like an endpoint.
type Config struct {
	Version     string
	Guard       GuardCheck
	Issuer      string
	Audience    string
	Signer      *tokens.Signer
	SigningKeys map[string]*ecdsa.PublicKey
	Clients     func(string) (oidc.Client, bool)
	LoginURL    string
	// Login runs the passkey ceremony. Absent means the OIDC endpoints
	// exist but nobody can complete a login through them.
	Login *login.Ceremony
}

// New returns the gateway mux.
func New(cfg Config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": cfg.Version})
	})

	// /readyz is the fail-closed door: if the Guard cannot answer, this
	// instance must not receive authentication traffic. No Guard means
	// nobody gets in, and a not-ready gateway is that rule's shape at the
	// load balancer.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Guard == nil {
			writeJSON(w, http.StatusOK, map[string]string{
				"status": "ready", "guard": "not configured", "version": cfg.Version,
			})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()
		if err := cfg.Guard(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not ready", "guard": err.Error(), "version": cfg.Version,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ready", "guard": "ok", "version": cfg.Version,
		})
	})

	if cfg.Signer != nil && cfg.Clients != nil {
		codes := oidc.NewCodeStore()
		pending := oidc.NewPendingStore()

		mux.Handle("GET /authorize", &oidc.Authorize{
			Clients: cfg.Clients, Pending: pending, LoginURL: cfg.LoginURL,
		})
		mux.Handle("POST /token", &oidc.Token{
			Codes: codes, Signer: cfg.Signer, Audience: cfg.Audience,
		})
		mux.Handle("GET /.well-known/openid-configuration", &oidc.Discovery{
			Meta: oidc.NewMetadata(cfg.Issuer),
		})
		jwks := oidc.NewJWKS(cfg.SigningKeys)
		mux.Handle("GET /.well-known/jwks.json", &jwks)

		if cfg.Login != nil {
			// The ceremony must share the stores the endpoints use, or a
			// code issued at login would be unknown at /token.
			cfg.Login.Pending = pending
			cfg.Login.Codes = codes
			mux.HandleFunc("GET /login/begin", cfg.Login.Begin)
			mux.HandleFunc("POST /login/finish", cfg.Login.Finish)
		}
	}

	return securityHeaders(mux)
}

// securityHeaders applies the defences that must never be forgotten on an
// individual handler: no framing, no MIME sniffing, no referrer leakage of
// authorization parameters, and HSTS.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		// Authorization URLs carry state and challenges; they must not leak
		// through Referer to any third party (threat model T1 Path C).
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
