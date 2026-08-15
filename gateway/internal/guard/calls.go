package guard

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	cryptov1 "github.com/AI-Powered-Management-Platform/Ai-Auth/gateway/gen/aiauth/crypto/v1"
)

// Call is who a Guard operation is for. Purpose is deliberately absent: each
// method below sets its own, so no caller can present the wrong one — the T9
// gate should never be able to reject us for a mistake we could prevent by
// construction.
type Call struct {
	TenantID  string
	SubjectID string
	// RequestID ties the gateway's log line to the Guard's audit record.
	// Generated when empty, because an unaudited key operation is not a
	// thing this system should be able to perform.
	RequestID string
}

func (c Call) context(purpose cryptov1.Purpose, subjectRequired bool) (*cryptov1.RequestContext, error) {
	if c.TenantID == "" {
		return nil, fmt.Errorf("guard: tenant id is required")
	}
	if subjectRequired && c.SubjectID == "" {
		return nil, fmt.Errorf("guard: subject id is required for row operations")
	}
	id := c.RequestID
	if id == "" {
		id = uuid.NewString()
	}
	return &cryptov1.RequestContext{
		TenantId:  c.TenantID,
		SubjectId: c.SubjectID,
		Purpose:   purpose,
		RequestId: id,
	}, nil
}

// VerifyPasskey checks one WebAuthn assertion. Expectations come from the
// gateway's stored ceremony state and are never taken from the client.
func (c *Client) VerifyPasskey(
	ctx context.Context,
	call Call,
	rpID, origin string,
	challenge []byte,
	credential *cryptov1.StoredCredential,
	assertion *cryptov1.Assertion,
) (*cryptov1.VerifyAssertionResponse, error) {
	rc, err := call.context(cryptov1.Purpose_PURPOSE_PASSKEY_LOGIN, false)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultCallTimeout)
	defer cancel()
	return c.svc.VerifyAssertion(ctx, &cryptov1.VerifyAssertionRequest{
		Context:           rc,
		RpId:              rpID,
		ExpectedOrigin:    origin,
		ExpectedChallenge: challenge,
		Credential:        credential,
		Assertion:         assertion,
	})
}

// EncryptField encrypts one value. An empty wrappedDek means first write and
// the Guard mints one; the returned key must be stored beside the ciphertext.
func (c *Client) EncryptField(
	ctx context.Context, call Call, plaintext, wrappedDek []byte,
) (ciphertext, dek []byte, err error) {
	rc, err := call.context(cryptov1.Purpose_PURPOSE_ROW_ENCRYPT, true)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultCallTimeout)
	defer cancel()
	resp, err := c.svc.EncryptField(ctx, &cryptov1.EncryptFieldRequest{
		Context: rc, Plaintext: plaintext, WrappedDek: wrappedDek,
	})
	if err != nil {
		return nil, nil, err
	}
	return resp.GetCiphertext(), resp.GetWrappedDek(), nil
}

func (c *Client) DecryptField(
	ctx context.Context, call Call, ciphertext, wrappedDek []byte,
) ([]byte, error) {
	rc, err := call.context(cryptov1.Purpose_PURPOSE_ROW_DECRYPT, true)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultCallTimeout)
	defer cancel()
	resp, err := c.svc.DecryptField(ctx, &cryptov1.DecryptFieldRequest{
		Context: rc, Ciphertext: ciphertext, WrappedDek: wrappedDek,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetPlaintext(), nil
}

// BlindIndex derives the searchable index for a value. Subject is not
// required: an index is often computed to find out who the subject is.
func (c *Client) BlindIndex(ctx context.Context, call Call, input []byte) ([]byte, error) {
	rc, err := call.context(cryptov1.Purpose_PURPOSE_BLIND_INDEX, false)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultCallTimeout)
	defer cancel()
	resp, err := c.svc.BlindIndex(ctx, &cryptov1.BlindIndexRequest{Context: rc, Input: input})
	if err != nil {
		return nil, err
	}
	return resp.GetIndex(), nil
}
