package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Revocations is the durable revocation store.
//
// The in-memory version lost every revocation on restart, which is the
// wrong direction to fail: a restart would resurrect sessions an operator
// had killed. Here the answer survives.
type Revocations struct {
	pool *pgxpool.Pool
}

func NewRevocations(pool *pgxpool.Pool) *Revocations {
	return &Revocations{pool: pool}
}

func (r *Revocations) RevokeToken(ctx context.Context, jti string, forgetAfter time.Time) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO gateway.revoked_tokens (jti, forget_after) VALUES ($1,$2)
		ON CONFLICT (jti) DO UPDATE SET forget_after = greatest(
			gateway.revoked_tokens.forget_after, excluded.forget_after)`,
		jti, forgetAfter)
	return err
}

// RevokeSubject records a cutoff. Re-revoking moves the cutoff forward only:
// greatest() prevents a replayed or out-of-order request from moving it
// backwards and un-revoking sessions.
func (r *Revocations) RevokeSubject(ctx context.Context, tenantID, subjectID string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO gateway.revocation_cutoffs (tenant_id, subject_id, cutoff)
		VALUES ($1,$2,now())
		ON CONFLICT (tenant_id, subject_id) DO UPDATE SET cutoff = greatest(
			gateway.revocation_cutoffs.cutoff, excluded.cutoff)`,
		tenantID, subjectID)
	return err
}

// RevokeTenant uses the empty subject id as the tenant-wide row, so one
// query answers both questions.
func (r *Revocations) RevokeTenant(ctx context.Context, tenantID string) error {
	return r.RevokeSubject(ctx, tenantID, "")
}

// IsRevoked answers in a single round trip. On any database error the caller
// must treat the session as revoked — see the wrapper in the sessions
// package. An unknown answer is never permission.
func (r *Revocations) IsRevoked(ctx context.Context, jti, tenantID, subjectID string, issuedAt time.Time) (bool, error) {
	var revoked bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM gateway.revoked_tokens WHERE jti = $1
		) OR EXISTS (
			SELECT 1 FROM gateway.revocation_cutoffs
			WHERE tenant_id = $2 AND subject_id IN ($3, '') AND cutoff >= $4
		)`, jti, tenantID, subjectID, issuedAt).Scan(&revoked)
	return revoked, err
}

// DeleteExpired drops token rows past their forget-after. Cutoffs are never
// deleted: removing one would resurrect every token it was killing.
func (r *Revocations) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM gateway.revoked_tokens WHERE forget_after < now()`)
	return tag.RowsAffected(), err
}
