// The gateway process. v1 skeleton: an HTTP server with health endpoints,
// hard timeouts, and graceful shutdown. Every request path added later
// inherits this envelope.
package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/guard"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/oidc"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/server"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/tokens"
)

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// version is stamped by the build; "dev" outside CI.
var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	addr := os.Getenv("GATEWAY_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	// Guard wiring: all-or-nothing. A partially configured Guard is a
	// misconfiguration, and misconfiguration fails closed at startup.
	var check server.GuardCheck
	if os.Getenv("GUARD_ADDR") != "" {
		g, err := guard.New(guard.Config{
			Addr:       os.Getenv("GUARD_ADDR"),
			CAFile:     os.Getenv("GUARD_CA_FILE"),
			CertFile:   os.Getenv("GUARD_CERT_FILE"),
			KeyFile:    os.Getenv("GUARD_KEY_FILE"),
			ServerName: envOr("GUARD_SERVER_NAME", "crypto"),
		})
		if err != nil {
			log.Error("guard config", "err", err)
			os.Exit(1)
		}
		defer g.Close()
		check = g.Probe
	}

	// OIDC wiring: a signer is required for the endpoints to exist at all.
	// v1 generates a development key at boot; production keys come from the
	// KMS/HSM path (docs/key-custody.md §4) and never live in this process.
	cfg := server.Config{Version: version, Guard: check, LoginURL: "/login"}
	if issuer := os.Getenv("OIDC_ISSUER"); issuer != "" {
		key, err := tokens.GenerateKey()
		if err != nil {
			log.Error("signing key", "err", err)
			os.Exit(1)
		}
		signer, err := tokens.NewSigner(issuer, "dev-1", key)
		if err != nil {
			log.Error("signer", "err", err)
			os.Exit(1)
		}
		cfg.Issuer = issuer
		cfg.Audience = envOr("OIDC_AUDIENCE", "api")
		cfg.Signer = signer
		cfg.SigningKeys = map[string]*ecdsa.PublicKey{"dev-1": &key.PublicKey}
		registry := oidc.NewRegistry()
		// Development seeding only. Real registration arrives with the
		// control plane; an empty registry refuses every client_id, which is
		// the correct posture for a server with no tenants yet.
		if dev := os.Getenv("OIDC_DEV_CLIENT_REDIRECT"); dev != "" {
			if err := registry.Register(oidc.Client{
				ID: envOr("OIDC_DEV_CLIENT_ID", "dev"), RedirectURIs: []string{dev},
			}); err != nil {
				log.Error("dev client registration", "err", err)
				os.Exit(1)
			}
			log.Warn("registered a development client", "redirect", dev)
		}
		cfg.Clients = registry.Lookup
		log.Warn("oidc enabled with a development signing key",
			"registered_clients", registry.Len())
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           server.New(cfg),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("gateway up", "addr", addr, "version", version)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("shutdown", "err", err)
			os.Exit(1)
		}
		log.Info("gateway stopped cleanly")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			os.Exit(1)
		}
	}
}
