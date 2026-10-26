// Package zitadelfiber serves the Zitadel identity provider login
// (zitadel.IDPLogin) with Fiber: the browser goes straight to the identity
// provider (e.g. Google), the app plays Zitadel's login UI with a service
// user, and the login ends at the client's usual callback (oidcfiber), which
// exchanges the code and verifies state, nonce and PKCE as for any login.
//
//	browser → Login → identity provider → Zitadel → Callback
//	→ client redirect URI (oidcfiber.Handler.Callback) → OnSuccess
//
// Wiring, next to the oidcfiber handler of the same client:
//
//	api := zitadel.New(client.Config().Issuer, servicePAT, nil)
//	h := zitadelfiber.New(client, zitadel.NewIDPLogin(api, googleIDPID), zitadelfiber.Options{
//		Tickets:     tickets,
//		CallbackURL: "https://api.example.com/auth/google/idp/callback",
//		OnError:     func(c *fiber.Ctx, err error) error { ... }, // see zitadel errors
//	})
//	app.Get("/auth/google/login", h.Login)
//	app.Get("/auth/google/idp/callback", h.Callback)
package zitadelfiber

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/vuongtlt13/oidcauth"
	"github.com/vuongtlt13/oidcauth/oidcfiber"
	"github.com/vuongtlt13/oidcauth/zitadel"
)

// ticketPrefix marks the tickets of this handler in a TicketStore shared
// with other uses.
const ticketPrefix = "zitadel-idp:"

// Options configures the handlers.
type Options struct {
	// Tickets carries the Zitadel auth request ID from Login to Callback.
	// Required. A ticket lives as long as the login flow (Config.FlowTTL).
	Tickets oidcauth.TicketStore
	// CallbackURL is the absolute URL of the Callback route. Required.
	// Login adds the ticket as query parameter TicketParam.
	CallbackURL string
	// TicketParam is the query parameter of CallbackURL carrying the ticket.
	// Defaults to "rq".
	TicketParam string
	// ReturnToParam is the query parameter of the login endpoint carrying the
	// path to return to after login. Defaults to "redirect".
	ReturnToParam string
	// LoginOptions adds per-request authorization options.
	LoginOptions func(c *fiber.Ctx) []oidcauth.LoginOption
	// OnError handles any failure before the client's callback: oidcauth
	// errors of the login start, oidcauth.ErrInvalidState for an unknown or
	// used ticket, zitadel errors (zitadel.ErrNotLinked, ErrIntentFailed, ...,
	// *zitadel.APIError) and network errors. zitadel.IsUserError tells
	// refusals from Zitadel being unavailable. Defaults to
	// oidcfiber.DefaultErrorHandler's 401/502.
	OnError func(c *fiber.Ctx, err error) error
}

// Handler serves the identity provider login of one oidcauth.Client.
type Handler struct {
	client *oidcauth.Client
	login  *zitadel.IDPLogin
	opts   Options
}

// New returns a Handler. It panics when Tickets or CallbackURL is missing.
func New(client *oidcauth.Client, login *zitadel.IDPLogin, opts Options) *Handler {
	if opts.Tickets == nil {
		panic("zitadelfiber: Options.Tickets is required")
	}
	if opts.CallbackURL == "" {
		panic("zitadelfiber: Options.CallbackURL is required")
	}
	if opts.TicketParam == "" {
		opts.TicketParam = "rq"
	}
	if opts.ReturnToParam == "" {
		opts.ReturnToParam = "redirect"
	}
	if opts.OnError == nil {
		opts.OnError = defaultErrorHandler
	}
	return &Handler{client: client, login: login, opts: opts}
}

// Login starts the client's login, completes Zitadel's authorization request
// server side and redirects the browser to the identity provider. The flow
// cookie is set as by oidcfiber.Handler.Login, so the client's callback
// verifies the login as usual.
func (h *Handler) Login(c *fiber.Ctx) error {
	ctx := c.UserContext()
	opts := []oidcauth.LoginOption{oidcauth.WithReturnTo(c.Query(h.opts.ReturnToParam))}
	if h.opts.LoginOptions != nil {
		opts = append(opts, h.opts.LoginOptions(c)...)
	}
	authURL, cookie, err := h.client.Start(ctx, opts...)
	if err != nil {
		return h.opts.OnError(c, err)
	}
	authRequestID, errorRedirect, err := h.login.Authorize(ctx, authURL)
	if err != nil {
		return h.opts.OnError(c, err)
	}
	oidcfiber.SetCookie(c, cookie)
	c.Set(fiber.HeaderCacheControl, "no-store")
	if authRequestID == "" {
		// Zitadel rejected the authorization request: errorRedirect is the
		// client's callback with the error, handled there.
		return c.Redirect(errorRedirect, fiber.StatusFound)
	}
	// Lives as long as the login flow: the user is at the identity provider
	// meanwhile.
	ticket, err := h.opts.Tickets.Put(ctx, ticketPrefix+authRequestID, h.client.Config().FlowTTL)
	if err != nil {
		return h.opts.OnError(c, fmt.Errorf("zitadelfiber: store ticket: %w", err))
	}
	callback, err := h.callbackURL(ticket)
	if err != nil {
		return h.opts.OnError(c, err)
	}
	redirect, err := h.login.StartIntent(ctx, callback, callback)
	if err != nil {
		return h.opts.OnError(c, err)
	}
	return c.Redirect(redirect, fiber.StatusFound)
}

// Callback is where Zitadel returns after the identity provider login: query
// id and token on success, error and error_description on failure, plus the
// ticket. On success it completes the Zitadel auth request and redirects the
// browser to the client's redirect URI with the code.
func (h *Handler) Callback(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	ctx := c.UserContext()
	value, err := h.opts.Tickets.Take(ctx, c.Query(h.opts.TicketParam))
	authRequestID, ok := strings.CutPrefix(value, ticketPrefix)
	if err != nil || !ok {
		if err == nil {
			err = oidcauth.ErrTicketNotFound
		}
		return h.opts.OnError(c, fmt.Errorf("%w: %w", oidcauth.ErrInvalidState, err))
	}
	if code := c.Query("error"); code != "" || c.Query("id") == "" {
		return h.opts.OnError(c, fmt.Errorf("%w: %s: %s", zitadel.ErrIntentFailed, code, c.Query("error_description")))
	}
	ua := &zitadel.UserAgent{IP: c.IP(), Description: c.Get(fiber.HeaderUserAgent)}
	callback, err := h.login.Finish(ctx, authRequestID, c.Query("id"), c.Query("token"), ua)
	if err != nil {
		return h.opts.OnError(c, err)
	}
	return c.Redirect(callback, fiber.StatusFound)
}

func (h *Handler) callbackURL(ticket string) (string, error) {
	u, err := url.Parse(h.opts.CallbackURL)
	if err != nil {
		return "", fmt.Errorf("zitadelfiber: callback url: %w", err)
	}
	q := u.Query()
	q.Set(h.opts.TicketParam, ticket)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func defaultErrorHandler(c *fiber.Ctx, err error) error {
	if oidcauth.IsUserError(err) || zitadel.IsUserError(err) || errors.Is(err, oidcauth.ErrTicketNotFound) {
		return c.Status(fiber.StatusUnauthorized).SendString("login failed")
	}
	return c.Status(fiber.StatusBadGateway).SendString("identity provider unavailable")
}
