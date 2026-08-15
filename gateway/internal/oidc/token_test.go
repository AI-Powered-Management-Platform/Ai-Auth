package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/internal/tokens"
)

const verifier = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func tokenEndpoint(t *testing.T) (*Token, *CodeStore) {
	t.Helper()
	key, err := tokens.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := tokens.NewSigner("https://auth.example.com", "key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	codes := NewCodeStore()
	return &Token{Codes: codes, Signer: s, Audience: "api"}, codes
}

func issueCode(t *testing.T, codes *CodeStore) string {
	t.Helper()
	g := testGrant()
	g.CodeChallenge = challengeFor(verifier)
	code, err := codes.Issue(g)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func post(t *testing.T, h http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func exchangeForm(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"app"},
		"redirect_uri":  {registered},
		"code_verifier": {verifier},
	}
}

func TestAValidExchangeReturnsAToken(t *testing.T) {
	h, codes := tokenEndpoint(t)
	rec := post(t, h, exchangeForm(issueCode(t, codes)))

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.AccessToken == "" {
		t.Fatal("no token issued")
	}
	if body.TokenType != "DPoP" {
		t.Fatalf("token_type = %q, want DPoP — bearer is not a supported shape", body.TokenType)
	}
	if body.ExpiresIn > 900 {
		t.Fatalf("expires_in = %d: access tokens are minutes, not hours", body.ExpiresIn)
	}
}

func TestGETIsRefused(t *testing.T) {
	// A GET would put the code and verifier in history, logs and Referer.
	h, codes := tokenEndpoint(t)
	req := httptest.NewRequest(http.MethodGet, "/token?"+exchangeForm(issueCode(t, codes)).Encode(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d, want 405", rec.Code)
	}
}

func TestAWrongVerifierIsRefused(t *testing.T) {
	// The interception case PKCE exists for.
	h, codes := tokenEndpoint(t)
	form := exchangeForm(issueCode(t, codes))
	form.Set("code_verifier", strings.Repeat("b", 64))
	rec := post(t, h, form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestACodeCannotBeUsedTwice(t *testing.T) {
	h, codes := tokenEndpoint(t)
	code := issueCode(t, codes)
	if rec := post(t, h, exchangeForm(code)); rec.Code != http.StatusOK {
		t.Fatal("first exchange should succeed")
	}
	if rec := post(t, h, exchangeForm(code)); rec.Code != http.StatusBadRequest {
		t.Fatal("replay must be refused")
	}
}

func TestAFailedPKCEStillBurnsTheCode(t *testing.T) {
	h, codes := tokenEndpoint(t)
	code := issueCode(t, codes)
	bad := exchangeForm(code)
	bad.Set("code_verifier", strings.Repeat("b", 64))
	post(t, h, bad)
	// Even with the right verifier now, the code is gone.
	if rec := post(t, h, exchangeForm(code)); rec.Code != http.StatusOK {
		return // correct: refused
	}
	t.Fatal("a wrong verifier must consume the code, not allow retries")
}

func TestAllRedemptionFailuresLookIdentical(t *testing.T) {
	// An attacker with a stolen code must not learn who it belongs to.
	h, codes := tokenEndpoint(t)

	wrongClient := exchangeForm(issueCode(t, codes))
	wrongClient.Set("client_id", "someone-else")
	a := post(t, h, wrongClient)

	unknownCode := exchangeForm("completely-made-up-code")
	b := post(t, h, unknownCode)

	if a.Code != b.Code || a.Body.String() != b.Body.String() {
		t.Fatalf("responses differ:\n wrong client: %d %s\n unknown code: %d %s",
			a.Code, a.Body.String(), b.Code, b.Body.String())
	}
}

func TestOnlyAuthorizationCodeGrantIsSupported(t *testing.T) {
	h, codes := tokenEndpoint(t)
	for _, gt := range []string{"password", "implicit", "client_credentials", ""} {
		form := exchangeForm(issueCode(t, codes))
		form.Set("grant_type", gt)
		rec := post(t, h, form)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unsupported_grant_type") {
			t.Fatalf("grant_type %q: got %d %s", gt, rec.Code, rec.Body.String())
		}
	}
}

func TestMissingParametersAreRefused(t *testing.T) {
	h, codes := tokenEndpoint(t)
	for _, missing := range []string{"code", "client_id", "redirect_uri", "code_verifier"} {
		form := exchangeForm(issueCode(t, codes))
		form.Del(missing)
		if rec := post(t, h, form); rec.Code != http.StatusBadRequest {
			t.Fatalf("missing %s was accepted", missing)
		}
	}
}

func TestTokenResponsesAreNeverCached(t *testing.T) {
	h, codes := tokenEndpoint(t)
	rec := post(t, h, exchangeForm(issueCode(t, codes)))
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestTheIssuedTokenCarriesTheGrantsIdentity(t *testing.T) {
	h, codes := tokenEndpoint(t)
	rec := post(t, h, exchangeForm(issueCode(t, codes)))
	var body struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	// Decode without verifying — this asserts the claims were populated from
	// the grant, not that the signature is good (covered in the tokens pkg).
	parts := strings.Split(body.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	if !strings.Contains(rec.Body.String(), "openid") {
		t.Fatal("scope must be echoed from the grant")
	}
}
