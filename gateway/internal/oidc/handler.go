package oidc

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
)

// Authorize serves the authorization endpoint.
type Authorize struct {
	// Clients resolves a registered client. Nil is a programming error, not
	// a runtime condition.
	Clients func(string) (Client, bool)
	Pending *PendingStore
	// LoginURL is where the user is sent to prove who they are. The pending
	// id travels in the query; nothing else does.
	LoginURL string
	Log      *slog.Logger
}

func (a *Authorize) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	req, err := ValidateAuthz(params, a.Clients)
	if err != nil {
		a.refuse(w, r, params, err)
		return
	}

	id, err := a.Pending.Put(*req)
	if err != nil {
		// A failing CSPRNG is not something to work around.
		a.log().Error("pending store", "err", err)
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	u, err := url.Parse(a.LoginURL)
	if err != nil {
		a.log().Error("login url", "err", err)
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	q := u.Query()
	q.Set("rid", id)
	u.RawQuery = q.Encode()

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// refuse decides whether an error may travel back through the redirect.
//
// The rule that matters: an unknown client or an unmatched redirect is shown
// to the USER, never redirected. Redirecting those would turn the endpoint
// into an open redirector — the attacker supplies the destination and the
// error is the excuse to visit it.
func (a *Authorize) refuse(w http.ResponseWriter, r *http.Request, params url.Values, err error) {
	w.Header().Set("Cache-Control", "no-store")

	switch {
	case errors.Is(err, ErrUnknownClient), errors.Is(err, ErrRedirectMismatch):
		a.log().Warn("authorize refused locally",
			"reason", err.Error(), "client_id", params.Get("client_id"))
		http.Error(w, "invalid client or redirect_uri", http.StatusBadRequest)
		return
	}

	code := "invalid_request"
	if errors.Is(err, ErrUnsupportedType) {
		code = "unsupported_response_type"
	}

	// Safe: the redirect was validated before this error could be reached.
	target, perr := RedirectWithError(params.Get("redirect_uri"), params.Get("state"), code, err.Error())
	if perr != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (a *Authorize) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}
