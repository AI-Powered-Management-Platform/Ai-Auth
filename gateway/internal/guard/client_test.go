package guard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	cryptov1 "github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/gen/aiauth/crypto/v1"
)

// fakeGuard rejects everything — the safest possible test double.
type fakeGuard struct {
	cryptov1.UnimplementedCryptoServiceServer
}

func (fakeGuard) VerifyAssertion(_ context.Context, _ *cryptov1.VerifyAssertionRequest) (*cryptov1.VerifyAssertionResponse, error) {
	return &cryptov1.VerifyAssertionResponse{
		Verdict: cryptov1.VerifyAssertionResponse_VERDICT_REJECTED,
		Reason:  "test_double_rejects_all",
	}, nil
}

// testPKI is a throwaway CA plus signed leaves, written into dir.
type testPKI struct {
	caPEM      []byte
	serverCert tls.Certificate
	caFile     string
	cert       string
	key        string
}

func newTestPKI(t *testing.T, dir string) *testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aiauth-dev-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leaf := func(cn string, usage x509.ExtKeyUsage) ([]byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			DNSNames:     []string{cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	srvCertPEM, srvKeyPEM := leaf("crypto", x509.ExtKeyUsageServerAuth)
	cliCertPEM, cliKeyPEM := leaf("gateway", x509.ExtKeyUsageClientAuth)
	serverCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	p := &testPKI{caPEM: caPEM, serverCert: serverCert}
	p.caFile = filepath.Join(dir, "ca.pem")
	p.cert = filepath.Join(dir, "client.pem")
	p.key = filepath.Join(dir, "client-key.pem")
	for f, b := range map[string][]byte{p.caFile: caPEM, p.cert: cliCertPEM, p.key: cliKeyPEM} {
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// startGuard serves fakeGuard behind real mutual TLS on a random port.
func startGuard(t *testing.T, p *testPKI) string {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.caPEM)
	creds := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{p.serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // mutual, not optional
	})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	cryptov1.RegisterCryptoServiceServer(srv, fakeGuard{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func TestRefusesIncompleteConfig(t *testing.T) {
	if _, err := New(Config{Addr: "x:1"}); err == nil {
		t.Fatal("client must refuse to exist without certificates — plaintext is not a mode")
	}
}

func TestMutualTLSRoundTrip(t *testing.T) {
	p := newTestPKI(t, t.TempDir())
	addr := startGuard(t, p)

	c, err := New(Config{Addr: addr, CAFile: p.caFile, CertFile: p.cert, KeyFile: p.key, ServerName: "crypto"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	resp, err := c.VerifyAssertion(context.Background(), &cryptov1.VerifyAssertionRequest{})
	if err != nil {
		t.Fatalf("mTLS round trip: %v", err)
	}
	if resp.GetVerdict() != cryptov1.VerifyAssertionResponse_VERDICT_REJECTED {
		t.Fatalf("verdict = %v, want the double's rejection", resp.GetVerdict())
	}
}

func TestWrongCAIsRefused(t *testing.T) {
	dir := t.TempDir()
	real := newTestPKI(t, dir)
	addr := startGuard(t, real)

	// A second, unrelated PKI: right filenames, wrong chain of trust.
	impDir := filepath.Join(dir, "impostor")
	if err := os.Mkdir(impDir, 0o700); err != nil {
		t.Fatal(err)
	}
	impostor := newTestPKI(t, impDir)

	c, err := New(Config{Addr: addr, CAFile: impostor.caFile, CertFile: impostor.cert, KeyFile: impostor.key, ServerName: "crypto"})
	if err != nil {
		t.Fatal(err) // construction succeeds; trust fails at the handshake
	}
	defer c.Close()

	if _, err := c.VerifyAssertion(context.Background(), &cryptov1.VerifyAssertionRequest{}); err == nil {
		t.Fatal("a certificate from the wrong CA must not produce a working channel")
	}
}
