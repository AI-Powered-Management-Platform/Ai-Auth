// Package guard is the gateway's only path to the crypto service. Transport
// rules come from the security model: mutual TLS always — plaintext gRPC is
// not a supported mode, including local development — TLS 1.3 minimum, and a
// deadline on every call, because a Guard that cannot answer in budget is a
// rejection, not a wait (fail-closed matrix).
package guard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	cryptov1 "github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/gen/aiauth/crypto/v1"
)

// DefaultCallTimeout bounds every Guard call. Generous for development; the
// production budget (~15 ms verify) is tuned by benchmarks, not guessed here.
const DefaultCallTimeout = 250 * time.Millisecond

// Config carries certificate PATHS, not certificate bytes — certs are mounted
// at runtime and never baked into an image or a binary.
type Config struct {
	Addr       string // e.g. "crypto:9090"
	CAFile     string // internal CA that signed the Guard's certificate
	CertFile   string // this gateway's client certificate
	KeyFile    string // this gateway's client key
	ServerName string // identity we require the Guard to prove, e.g. "crypto"
}

// Client is a thin, deadline-enforcing wrapper over the generated stub.
type Client struct {
	conn *grpc.ClientConn
	svc  cryptov1.CryptoServiceClient
}

// New fails closed: no certificates, no client. There is deliberately no
// insecure option to reach for under deadline pressure.
func New(cfg Config) (*Client, error) {
	if cfg.Addr == "" || cfg.CAFile == "" || cfg.CertFile == "" || cfg.KeyFile == "" || cfg.ServerName == "" {
		return nil, fmt.Errorf("guard: incomplete mTLS config: every field is required")
	}

	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("guard: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("guard: CA file %q contains no usable certificates", cfg.CAFile)
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("guard: load client keypair: %w", err)
	}

	creds := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   cfg.ServerName,
	})

	conn, err := grpc.NewClient(cfg.Addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("guard: dial: %w", err)
	}
	return &Client{conn: conn, svc: cryptov1.NewCryptoServiceClient(conn)}, nil
}

// VerifyAssertion forwards a passkey verification with a hard deadline. The
// caller's context may tighten the deadline; it can never remove it.
func (c *Client) VerifyAssertion(ctx context.Context, req *cryptov1.VerifyAssertionRequest) (*cryptov1.VerifyAssertionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultCallTimeout)
	defer cancel()
	return c.svc.VerifyAssertion(ctx, req)
}

func (c *Client) Close() error { return c.conn.Close() }
