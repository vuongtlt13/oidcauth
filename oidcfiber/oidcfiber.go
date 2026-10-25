// Package oidcfiber adapts oidcauth to Fiber v2.
//
//	h := oidcfiber.New(client, oidcfiber.Options{
//		OnSuccess: func(c *fiber.Ctx, res *oidcauth.Result) error {
//			user, err := users.FromIdentity(c.UserContext(), res.Identity) // app decides
//			if err != nil { return err }
//			token, _ := sessions.Issue(user)
//			ticket, _ := tickets.Put(c.UserContext(), token, time.Minute)
//			return c.Redirect("/auth/callback?ticket=" + url.QueryEscape(ticket) +
//				"&redirect=" + url.QueryEscape(oidcauth.SafeReturnTo(res.ReturnTo, "/")))
//		},
//	})
//	app.Get("/api/v1/auth/oidc/login", h.Login)
//	app.Get("/api/v1/auth/oidc/callback", h.Callback)
//	app.Post("/api/v1/auth/oidc/callback", h.Callback) // only with response_mode=form_post
//	app.Post("/api/v1/auth/oidc/backchannel-logout", h.BackChannelLogout(func(c *fiber.Ctx, t *oidcauth.LogoutToken) error {
//		return sessions.EndProviderSession(c.UserContext(), t.Subject, t.SessionID)
//	}))
package oidcfiber

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/vuongtlt13/oidcauth"
)

// Options configures the handlers.
type Options struct {
	// ReturnToParam is the query parameter of the login endpoint carrying the
	// path to return to after login. Defaults to "redirect".
	ReturnToParam string
	// LoginOptions adds per-request authorization options (e.g. an org scope
	// chosen from the request).
	LoginOptions func(c *fiber.Ctx) []oidcauth.LoginOption
	// OnSuccess receives the verified login. Required. It typically maps the
	// identity to a local user, issues the app session and redirects.
	OnSuccess func(c *fiber.Ctx, res *oidcauth.Result) error
	// OnError handles any failure (start or callback). Defaults to a 401/502
	// plain-text response; SPAs usually redirect to their login page with an
	// error code instead.
	OnError func(c *fiber.Ctx, err error) error
}

// Handler exposes Fiber handlers for one oidcauth.Client.
type Handler struct {
	client *oidcauth.Client
	opts   Options
}

// New returns a Handler. It panics when OnSuccess is nil.
func New(client *oidcauth.Client, opts Options) *Handler {
	if opts.OnSuccess == nil {
		panic("oidcfiber: Options.OnSuccess is required")
	}
	if opts.ReturnToParam == "" {
		opts.ReturnToParam = "redirect"
	}
	if opts.OnError == nil {
		opts.OnError = DefaultErrorHandler
	}
	return &Handler{client: client, opts: opts}
}

// Login starts the authorization request and redirects to the provider.
func (h *Handler) Login(c *fiber.Ctx) error {
	opts := []oidcauth.LoginOption{oidcauth.WithReturnTo(c.Query(h.opts.ReturnToParam))}
	if h.opts.LoginOptions != nil {
		opts = append(opts, h.opts.LoginOptions(c)...)
	}
	authURL, cookie, err := h.client.Start(c.UserContext(), opts...)
	if err != nil {
		return h.opts.OnError(c, err)
	}
	SetCookie(c, cookie)
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Redirect(authURL, fiber.StatusFound)
}

// Callback completes the login and calls OnSuccess or OnError. Mount it on GET
// (response_mode=query) and, when ResponseModeFormPost is used, on POST too.
func (h *Handler) Callback(c *fiber.Ctx) error {
	query := CallbackValues(c)
	state := query.Get("state")
	c.Set(fiber.HeaderCacheControl, "no-store")
	if state != "" {
		defer SetCookie(c, h.client.ClearCookie(state))
	}
	var cookieValue string
	if state != "" {
		cookieValue = c.Cookies(h.client.CookieNameFor(state))
	}
	res, err := h.client.Finish(c.UserContext(), query, cookieValue)
	if err != nil {
		return h.opts.OnError(c, err)
	}
	return h.opts.OnSuccess(c, res)
}

// BackChannelLogout returns a handler for the back-channel logout URI
// registered at the provider (OpenID Connect Back-Channel Logout 1.0). It
// verifies the POSTed `logout_token` and calls onLogout, which ends the app
// sessions of LogoutToken.Subject and/or LogoutToken.SessionID. It answers
// 200 on success, 400 for an invalid token and 501 when onLogout fails (the
// spec's error status), always with Cache-Control: no-store.
func (h *Handler) BackChannelLogout(onLogout func(c *fiber.Ctx, t *oidcauth.LogoutToken) error) fiber.Handler {
	if onLogout == nil {
		panic("oidcfiber: BackChannelLogout needs onLogout")
	}
	return func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderCacheControl, "no-store")
		raw := c.FormValue("logout_token")
		if raw == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_request"})
		}
		token, err := h.client.VerifyLogoutToken(c.UserContext(), raw)
		if err != nil {
			if errors.Is(err, oidcauth.ErrInvalidLogoutToken) {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_request"})
			}
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "temporarily_unavailable"})
		}
		if err := onLogout(c, token); err != nil {
			return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{"error": "logout_failed"})
		}
		return c.SendStatus(fiber.StatusOK)
	}
}

// DefaultErrorHandler answers 401 for login failures and 502 when the
// provider cannot be reached, without leaking internal details.
func DefaultErrorHandler(c *fiber.Ctx, err error) error {
	if oidcauth.IsUserError(err) {
		return c.Status(fiber.StatusUnauthorized).SendString("login failed")
	}
	return c.Status(fiber.StatusBadGateway).SendString("identity provider unavailable")
}

// QueryValues converts the request query string to url.Values.
func QueryValues(c *fiber.Ctx) url.Values {
	values, _ := url.ParseQuery(string(c.Request().URI().QueryString()))
	return values
}

// CallbackValues returns the authorization response parameters: the query
// string, or the form body of a POST (response_mode=form_post).
func CallbackValues(c *fiber.Ctx) url.Values {
	if c.Method() != fiber.MethodPost {
		return QueryValues(c)
	}
	values := url.Values{}
	c.Request().PostArgs().VisitAll(func(k, v []byte) {
		values.Add(string(k), string(v))
	})
	return values
}

// SetCookie writes a net/http cookie through Fiber.
func SetCookie(c *fiber.Ctx, ck *http.Cookie) {
	fc := &fiber.Cookie{
		Name:     ck.Name,
		Value:    ck.Value,
		Path:     ck.Path,
		Domain:   ck.Domain,
		MaxAge:   ck.MaxAge,
		Expires:  ck.Expires,
		Secure:   ck.Secure,
		HTTPOnly: ck.HttpOnly,
	}
	switch ck.SameSite {
	case http.SameSiteStrictMode:
		fc.SameSite = fiber.CookieSameSiteStrictMode
	case http.SameSiteNoneMode:
		fc.SameSite = fiber.CookieSameSiteNoneMode
	default:
		fc.SameSite = fiber.CookieSameSiteLaxMode
	}
	if ck.MaxAge < 0 {
		// fasthttp omits a non-positive Max-Age; deletion relies on the past
		// Expires set by oidcauth.ClearCookie.
		fc.MaxAge = 0
	}
	c.Cookie(fc)
}
