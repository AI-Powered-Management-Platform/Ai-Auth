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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

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

// Probe checks channel health, not business success. An empty VerifyAssertion
// is REJECTED by the Guard's T9 gate — and that rejection arriving as a
// proper gRPC status proves the mTLS channel end to end. Transport failure
// (unreachable, handshake, deadline) is the only unhealthy answer.
func (c *Client) Probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, DefaultCallTimeout)
	defer cancel()
	// WaitForReady rides out cold starts: if the Guard is still booting or
	// DNS has not settled, the probe waits for its deadline instead of
	// failing instantly on a transient resolver state.
	_, err := c.svc.VerifyAssertion(ctx, &cryptov1.VerifyAssertionRequest{}, grpc.WaitForReady(true))
	if err == nil {
		return nil // unexpected at v1, but an answer is an answer
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.PermissionDenied, codes.Unimplemented:
		return nil // the Guard answered: channel healthy, gate working
	default:
		return fmt.Errorf("guard unreachable: %w", err)
	}
}
