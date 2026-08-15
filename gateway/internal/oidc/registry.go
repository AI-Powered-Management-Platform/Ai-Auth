package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

var (
	ErrClientExists  = errors.New("client id already registered")
	ErrNoRedirectURI = errors.New("at least one redirect_uri is required")
	ErrBadRedirect   = errors.New("redirect_uri is not acceptable")
)

// Registry holds registered clients. Reads dominate by orders of magnitude
// (every authorization request) so it is read-locked, and registration is
// where all the validation lives — a bad redirect must be impossible to
// store, not merely refused later.
type Registry struct {
	mu      sync.RWMutex
	clients map[string]Client
}

func NewRegistry() *Registry {
	return &Registry{clients: make(map[string]Client)}
}

// Register validates and stores a client. Every redirect URI is checked here
// so that ValidateAuthz can stay a pure exact-match: the moment a wildcard
// or a fragment reaches storage, the exactness downstream stops meaning
// anything.
func (r *Registry) Register(c Client) error {
	if c.ID == "" {
		return errors.New("client id is required")
	}
	if len(c.RedirectURIs) == 0 {
		return ErrNoRedirectURI
	}
	for _, raw := range c.RedirectURIs {
		if err := validateRedirectURI(raw); err != nil {
			return fmt.Errorf("%w: %q: %s", ErrBadRedirect, raw, err)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.clients[c.ID]; exists {
		// Silent overwrite would let a registration bug or a replayed admin
		// request retarget an existing client's redirects.
		return ErrClientExists
	}
	// Copy the slice: the caller must not be able to mutate registered
	// redirects after the fact.
	uris := make([]string, len(c.RedirectURIs))
	copy(uris, c.RedirectURIs)
	r.clients[c.ID] = Client{ID: c.ID, RedirectURIs: uris}
	return nil
}

// Lookup is the function ValidateAuthz expects.
func (r *Registry) Lookup(id string) (Client, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[id]
	return c, ok
}

func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.clients)
}

// validateRedirectURI enforces what a registered redirect may be. Each rule
// exists because its absence has produced a real token theft.
func validateRedirectURI(raw string) error {
	if raw == "" {
		return errors.New("empty")
	}
	// Wildcards are never legitimate: matching is exact, so a stored
	// wildcard is either a mistake or an attempt to widen the target set.
	if strings.ContainsAny(raw, "*?") {
		return errors.New("wildcards are not permitted")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("unparsable")
	}
	if !u.IsAbs() {
		return errors.New("must be absolute")
	}
	// A fragment is never sent to the server, so a registered one can never
	// be matched — storing it guarantees a broken client.
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("must not contain a fragment")
	}
	if u.Host == "" && u.Scheme != "" && !strings.HasPrefix(raw, u.Scheme+"://") {
		return errors.New("custom scheme URIs must use scheme://host form")
	}

	switch u.Scheme {
	case "https":
		return nil
	case "http":
		// Plain HTTP leaks the authorization code to the network. Loopback
		// is the documented exception for native apps (RFC 8252 §7.3).
		if isLoopback(u.Hostname()) {
			return nil
		}
		return errors.New("http is only permitted for loopback redirects")
	default:
		// Custom schemes are how mobile apps receive callbacks. They are
		// permitted, but docs/mobile-integration.md §1 tells clients to use
		// verified https links instead: a scheme is first-come-first-served
		// across every app on the device.
		if u.Scheme == "" {
			return errors.New("scheme is required")
		}
		return nil
	}
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}
