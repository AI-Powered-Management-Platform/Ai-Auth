// Package store holds the Postgres implementations of the gateway's state.
//
// The in-memory versions were correct for one process. These are correct for
// several, which is a different problem: single-use has to be enforced by the
// database, not by a mutex, or two replicas both let the same code through.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Open connects and verifies the connection before returning. A pool that
// cannot reach the database must fail at startup, not on the first login.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	// Bounded, because an unbounded pool turns a traffic spike into a
	// database outage that takes every replica with it.
	cfg.MaxConns = 16
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return pool, nil
}

var ErrNotFound = errors.New("not found")

// Codes is the authorization code store, backed by Postgres.
type Codes struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewCodes(pool *pgxpool.Pool) *Codes {
	return &Codes{pool: pool, now: time.Now}
}

// Grant mirrors oidc.Grant. Duplicated rather than imported so the store
// package does not depend on the HTTP layer.
type Grant struct {
	ClientID      string
	RedirectURI   string
	Scope         string
	Nonce         string
	CodeChallenge string
	SubjectID     string
	TenantID      string
	AuthTime      time.Time
}

func (c *Codes) Insert(ctx context.Context, code string, g Grant, expiresAt time.Time) error {
	_, err := c.pool.Exec(ctx, `
		INSERT INTO gateway.auth_codes
			(code, tenant_id, subject_id, client_id, redirect_uri, scope,
			 nonce, code_challenge, auth_time, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		code, g.TenantID, g.SubjectID, g.ClientID, g.RedirectURI, g.Scope,
		g.Nonce, g.CodeChallenge, g.AuthTime, expiresAt)
	return err
}

// Redeem consumes a code exactly once.
//
// DELETE ... RETURNING is the whole design: the delete and the read are one
// atomic statement, so two replicas racing the same code cannot both receive
// a row. A SELECT-then-DELETE would let both win.
//
// The row is deleted before its client and redirect are checked, matching
// the in-memory store: a wrong client burns the code rather than getting an
// oracle to probe with.
func (c *Codes) Redeem(ctx context.Context, code, clientID, redirectURI string) (*Grant, error) {
	var g Grant
	var expiresAt time.Time

	err := c.pool.QueryRow(ctx, `
		DELETE FROM gateway.auth_codes
		WHERE code = $1
		RETURNING tenant_id, subject_id, client_id, redirect_uri, scope,
		          coalesce(nonce,''), code_challenge, auth_time, expires_at`,
		code).Scan(&g.TenantID, &g.SubjectID, &g.ClientID, &g.RedirectURI,
		&g.Scope, &g.Nonce, &g.CodeChallenge, &g.AuthTime, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if c.now().After(expiresAt) {
		return nil, ErrNotFound
	}
	// Undifferentiated on purpose: an attacker with a stolen code must not
	// learn which client it belongs to.
	if g.ClientID != clientID || g.RedirectURI != redirectURI {
		return nil, ErrNotFound
	}
	return &g, nil
}

// DeleteExpired removes codes that can no longer be redeemed. Called by the
// worker; the redemption path does not pay for housekeeping.
func (c *Codes) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := c.pool.Exec(ctx, `DELETE FROM gateway.auth_codes WHERE expires_at < now()`)
	return tag.RowsAffected(), err
}
