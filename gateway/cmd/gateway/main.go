// The gateway process. v1 skeleton: an HTTP server with health endpoints,
// hard timeouts, and graceful shutdown. Every request path added later
// inherits this envelope.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/guard"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/server"
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

	srv := &http.Server{
		Addr:              addr,
		Handler:           server.New(version, check),
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
