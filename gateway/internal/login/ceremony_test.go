package login

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	cryptov1 "github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/gen/aiauth/crypto/v1"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/guard"
	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/oidc"
)

const (
	rpID     = "auth.example.com"
	origin   = "https://auth.example.com"
	redirect = "https://app.example.com/cb"
)

// fakeGuard stands in for the crypto service. Verification itself is tested
// in the crypto crate; here the concern is what the ceremony does with each
// possible answer.
type fakeGuard struct {
	verdict cryptov1.VerifyAssertionResponse_Verdict
	err     error
	calls   int
	lastCtx guard.Call
}

func (f *fakeGuard) VerifyPasskey(_ context.Context, call guard.Call, _, _ string,
	_ []byte, _ *cryptov1.StoredCredential, _ *cryptov1.Assertion,
) (*cryptov1.VerifyAssertionResponse, error) {
	f.calls++
	f.lastCtx = call
	if f.err != nil {
		return nil, f.err
	}
	v := f.verdict
	if v == 0 {
		v = cryptov1.VerifyAssertionResponse_VERDICT_VERIFIED
	}
	return &cryptov1.VerifyAssertionResponse{Verdict: v, NewSignCount: 7}, nil
}

type harness struct {
	c       *Ceremony
	g       *fakeGuard
	pending *oidc.PendingStore
	codes   *oidc.CodeStore
	credID  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	creds := NewCredentials()
	creds.Add(Credential{
		ID: "cred-1", TenantID: "tenant-1", SubjectID: "user-1",
		PublicKey: key.PublicKey.X.Bytes(), SignCount: 3,
	})
	g := &fakeGuard{}
	h := &harness{
		g: g, pending: oidc.NewPendingStore(), codes: oidc.NewCodeStore(), credID: "cred-1",
	}
	h.c = &Ceremony{
		Guard: g, Challenges: NewChallenges(), Credentials: creds,
		Pending: h.pending, Codes: h.codes, RPID: rpID, Origin: origin,
	}
	return h
}

func (h *harness) startAuthz(t *testing.T) string {
	t.Helper()
	rid, err := h.pending.Put(oidc.AuthzRequest{
		ClientID: "app", RedirectURI: redirect, Scope: "openid",
		State: "xyz", CodeChallenge: "chal",
	})
	if err != nil {
		t.Fatal(err)
	}
	return rid
}

func (h *harness) begin(t *testing.T, rid string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.c.Begin(rec, httptest.NewRequest(http.MethodGet, "/login/begin?rid="+rid, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("begin: %d %s", rec.Code, rec.Body.String())
	}
}

func (h *harness) finish(t *testing.T, rid, credID string) *httptest.ResponseRecorder {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	body, _ := json.Marshal(finishRequest{
		RID: rid, CredentialID: credID,
		AuthenticatorData: b64(make([]byte, 37)),
		ClientDataJSON:    b64([]byte(`{"type":"webauthn.get"}`)),
		Signature:         b64(make([]byte, 64)),
	})
	req := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	h.c.Finish(rec, req)
	return rec
}

func redirectOf(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	var body finishResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(body.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestASuccessfulCeremonyIssuesACode(t *testing.T) {
	h := newHarness(t)
	rid := h.startAuthz(t)
	h.begin(t, rid)

	rec := h.finish(t, rid, h.credID)
	if rec.Code != http.StatusOK {
		t.Fatalf("finish: %d %s", rec.Code, rec.Body.String())
	}
	u := redirectOf(t, rec)
	if u.Host != "app.example.com" {
		t.Fatalf("redirected to %q", u.Host)
	}
	if u.Query().Get("code") == "" {
		t.Fatal("no authorization code issued")
	}
	if u.Query().Get("state") != "xyz" {
		t.Fatal("state must be echoed unchanged: it is the client's CSRF defence")
	}
}

func TestTheGuardReceivesTheCredentialsIdentity(t *testing.T) {
	h := newHarness(t)
	rid := h.startAuthz(t)
	h.begin(t, rid)
	h.finish(t, rid, h.credID)

	if h.g.lastCtx.TenantID != "tenant-1" || h.g.lastCtx.SubjectID != "user-1" {
		t.Fatalf("guard call carried %+v", h.g.lastCtx)
	}
}

func TestAChallengeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	rid := h.startAuthz(t)
	h.begin(t, rid)

	if rec := h.finish(t, rid, h.credID); rec.Code != http.StatusOK {
		t.Fatal("first attempt should succeed")
	}
	if rec := h.finish(t, rid, h.credID); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay got %d, want 401", rec.Code)
	}
}

func TestAFailedAttemptStillConsumesTheChallenge(t *testing.T) {
	h := newHarness(t)
	h.g.verdict = cryptov1.VerifyAssertionResponse_VERDICT_REJECTED
	rid := h.startAuthz(t)
	h.begin(t, rid)

	if rec := h.finish(t, rid, h.credID); rec.Code != http.StatusUnauthorized {
		t.Fatal("rejected assertion must fail")
	}
	// Even a now-good attempt must fail: one challenge, one attempt.
	h.g.verdict = cryptov1.VerifyAssertionResponse_VERDICT_VERIFIED
	if rec := h.finish(t, rid, h.credID); rec.Code != http.StatusUnauthorized {
		t.Fatal("a spent challenge must not be reusable")
	}
}

func TestFinishWithoutBeginIsRefused(t *testing.T) {
	h := newHarness(t)
	rid := h.startAuthz(t)
	if rec := h.finish(t, rid, h.credID); rec.Code != http.StatusUnauthorized {
		t.Fatal("an assertion without a challenge must be refused")
	}
	if h.g.calls != 0 {
		t.Fatal("the Guard must not be called without a live challenge")
	}
}

func TestUnknownCredentialAndRejectedAssertionLookIdentical(t *testing.T) {
	// Whether a credential exists is not something an unauthenticated caller
	// may learn.
	h := newHarness(t)
	rid := h.startAuthz(t)
	h.begin(t, rid)
	unknown := h.finish(t, rid, "no-such-credential")

	h2 := newHarness(t)
	h2.g.verdict = cryptov1.VerifyAssertionResponse_VERDICT_REJECTED
	rid2 := h2.startAuthz(t)
	h2.begin(t, rid2)
	rejected := h2.finish(t, rid2, h2.credID)

	if unknown.Code != rejected.Code || unknown.Body.String() != rejected.Body.String() {
		t.Fatalf("responses differ:\n unknown:  %d %s\n rejected: %d %s",
			unknown.Code, unknown.Body.String(), rejected.Code, rejected.Body.String())
	}
}

func TestAnUnreachableGuardIsNeverALogin(t *testing.T) {
	// No Guard means nobody gets in — the fail-closed matrix, at the login.
	h := newHarness(t)
	h.g.err = errors.New("no route to guard")
	rid := h.startAuthz(t)
	h.begin(t, rid)

	rec := h.finish(t, rid, h.credID)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503 — an unreachable Guard must not authenticate", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "redirect_to") {
		t.Fatal("no code may be issued when the Guard cannot answer")
	}
}

func TestTheSignCountIsPersisted(t *testing.T) {
	// Without this, clone detection compares against a stale value forever.
	h := newHarness(t)
	rid := h.startAuthz(t)
	h.begin(t, rid)
	h.finish(t, rid, h.credID)

	c, err := h.c.Credentials.Get(h.credID)
	if err != nil {
		t.Fatal(err)
	}
	if c.SignCount != 7 {
		t.Fatalf("sign count = %d, want the authenticator's newest value", c.SignCount)
	}
}

func TestTheCodeCarriesTheAuthenticatedIdentity(t *testing.T) {
	h := newHarness(t)
	rid := h.startAuthz(t)
	h.begin(t, rid)
	rec := h.finish(t, rid, h.credID)

	u := redirectOf(t, rec)
	grant, err := h.codes.Redeem(u.Query().Get("code"), "app", redirect)
	if err != nil {
		t.Fatal(err)
	}
	if grant.SubjectID != "user-1" || grant.TenantID != "tenant-1" {
		t.Fatalf("grant identity = %s/%s", grant.TenantID, grant.SubjectID)
	}
	if grant.CodeChallenge != "chal" {
		t.Fatal("the PKCE challenge must survive from /authorize to the code")
	}
}

func TestBeginRequiresARequestID(t *testing.T) {
	h := newHarness(t)
	rec := httptest.NewRecorder()
	h.c.Begin(rec, httptest.NewRequest(http.MethodGet, "/login/begin", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestAnExpiredAuthorizationCannotBeCompleted(t *testing.T) {
	h := newHarness(t)
	rid := h.startAuthz(t)
	h.begin(t, rid)
	// The user authenticates, but the authorization request is already gone.
	h.pending.Take(rid)
	if rec := h.finish(t, rid, h.credID); rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}
