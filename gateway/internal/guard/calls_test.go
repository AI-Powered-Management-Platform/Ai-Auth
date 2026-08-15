package guard

import (
	"context"
	"testing"

	cryptov1 "github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/gen/aiauth/crypto/v1"
)

// recordingGuard captures the RequestContext each call arrives with, so the
// tests can assert on what the gateway actually sent rather than on what the
// wrapper claims to send.
type recordingGuard struct {
	cryptov1.UnimplementedCryptoServiceServer
	last *cryptov1.RequestContext
}

func (g *recordingGuard) VerifyAssertion(_ context.Context, r *cryptov1.VerifyAssertionRequest) (*cryptov1.VerifyAssertionResponse, error) {
	g.last = r.GetContext()
	return &cryptov1.VerifyAssertionResponse{Verdict: cryptov1.VerifyAssertionResponse_VERDICT_REJECTED}, nil
}

func (g *recordingGuard) EncryptField(_ context.Context, r *cryptov1.EncryptFieldRequest) (*cryptov1.EncryptFieldResponse, error) {
	g.last = r.GetContext()
	return &cryptov1.EncryptFieldResponse{Ciphertext: []byte("ct"), WrappedDek: []byte("dek")}, nil
}

func (g *recordingGuard) DecryptField(_ context.Context, r *cryptov1.DecryptFieldRequest) (*cryptov1.DecryptFieldResponse, error) {
	g.last = r.GetContext()
	return &cryptov1.DecryptFieldResponse{Plaintext: []byte("pt")}, nil
}

func (g *recordingGuard) BlindIndex(_ context.Context, r *cryptov1.BlindIndexRequest) (*cryptov1.BlindIndexResponse, error) {
	g.last = r.GetContext()
	return &cryptov1.BlindIndexResponse{Index: make([]byte, 32)}, nil
}

func recordingClient(t *testing.T) (*Client, *recordingGuard) {
	t.Helper()
	p := newTestPKI(t, t.TempDir())
	rec := &recordingGuard{}
	addr := startGuardWith(t, p, rec)
	c, err := New(Config{Addr: addr, CAFile: p.caFile, CertFile: p.cert, KeyFile: p.key, ServerName: "crypto"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, rec
}

func TestEachOperationSendsItsOwnPurpose(t *testing.T) {
	c, rec := recordingClient(t)
	call := Call{TenantID: "t1", SubjectID: "s1"}
	ctx := context.Background()

	cases := []struct {
		name string
		run  func() error
		want cryptov1.Purpose
	}{
		{"verify", func() error {
			_, err := c.VerifyPasskey(ctx, call, "rp", "https://rp", nil, nil, nil)
			return err
		}, cryptov1.Purpose_PURPOSE_PASSKEY_LOGIN},
		{"encrypt", func() error {
			_, _, err := c.EncryptField(ctx, call, []byte("x"), nil)
			return err
		}, cryptov1.Purpose_PURPOSE_ROW_ENCRYPT},
		{"decrypt", func() error {
			_, err := c.DecryptField(ctx, call, []byte("x"), []byte("d"))
			return err
		}, cryptov1.Purpose_PURPOSE_ROW_DECRYPT},
		{"index", func() error {
			_, err := c.BlindIndex(ctx, call, []byte("x"))
			return err
		}, cryptov1.Purpose_PURPOSE_BLIND_INDEX},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err != nil {
				t.Fatal(err)
			}
			if got := rec.last.GetPurpose(); got != tc.want {
				t.Fatalf("purpose = %v, want %v", got, tc.want)
			}
			if rec.last.GetTenantId() != "t1" {
				t.Fatal("tenant id must reach the Guard")
			}
			if rec.last.GetRequestId() == "" {
				t.Fatal("request id must never be empty: every key op is audited")
			}
		})
	}
}

func TestRequestIDIsGeneratedWhenAbsent(t *testing.T) {
	c, rec := recordingClient(t)
	if _, err := c.BlindIndex(context.Background(), Call{TenantID: "t1"}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	first := rec.last.GetRequestId()
	if _, err := c.BlindIndex(context.Background(), Call{TenantID: "t1"}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if rec.last.GetRequestId() == first {
		t.Fatal("each operation needs its own audit id")
	}
}

func TestSuppliedRequestIDIsPreserved(t *testing.T) {
	c, rec := recordingClient(t)
	call := Call{TenantID: "t1", RequestID: "req-from-http-layer"}
	if _, err := c.BlindIndex(context.Background(), call, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if rec.last.GetRequestId() != "req-from-http-layer" {
		t.Fatal("a caller-supplied id must survive, so logs correlate end to end")
	}
}

func TestATenantlessCallNeverLeavesTheGateway(t *testing.T) {
	c, rec := recordingClient(t)
	if _, err := c.BlindIndex(context.Background(), Call{}, []byte("x")); err == nil {
		t.Fatal("a call without a tenant must be refused locally")
	}
	if rec.last != nil {
		t.Fatal("the malformed call must not reach the Guard at all")
	}
}

func TestRowOperationsRequireASubject(t *testing.T) {
	c, _ := recordingClient(t)
	call := Call{TenantID: "t1"} // no subject
	if _, _, err := c.EncryptField(context.Background(), call, []byte("x"), nil); err == nil {
		t.Fatal("encrypt without a subject must be refused")
	}
	if _, err := c.DecryptField(context.Background(), call, []byte("x"), []byte("d")); err == nil {
		t.Fatal("decrypt without a subject must be refused")
	}
}
