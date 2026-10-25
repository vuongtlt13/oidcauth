# oidcauth

`oidcauth` is a thin OpenID Connect relying party for browser login in Go
services. It adds **OIDC login next to local (username/password) login**
without changing how your app keeps users signed in.

It is built on [`github.com/zitadel/oidc/v3`](https://github.com/zitadel/oidc), which
is OpenID certified. Discovery, JWKS, the code exchange and ID token checks
come from that library. `oidcauth` adds the parts every app otherwise
rewrites:

- Authorization Code flow with **PKCE (S256)**, `state` and `nonce`.
- An encrypted, short-lived **flow cookie** that holds state, nonce, the PKCE
  verifier and the return path. It uses AES-256-GCM, is bound to `state`,
  and is set per login, so several tabs can log in at once.
- **ID token verification**: signature checked against the JWKS, plus `iss`,
  `aud`, `azp`, `exp`, `iat`, `nonce` and `at_hash`. Userinfo claims are then
  merged in. `sub`/`iss` and other protected claims are never overridden by
  userinfo.
- A normalized **`Identity`**: issuer, subject, email, `email_verified`,
  profile fields, roles (Zitadel project roles out of the box) and raw claims.
- `SafeReturnTo`, which prevents open redirects.
- A single-use **`TicketStore`**, so the callback can hand a session token to
  an SPA without putting it in a URL.
- RP-initiated logout via `LogoutURL`.
- A **Fiber v2 adapter** (`oidcfiber`) and an in-process **fake provider**
  (`oidctest`) for end-to-end tests.

`oidcauth` deliberately does **not** do the following. Each application
decides them:

- Create, link or reject local users. The app receives an `Identity` and does
  whatever its policy says.
- Issue sessions or JWTs. Keep using your existing token and middleware.

## Install

```bash
go get github.com/vuongtlt13/oidcauth
```

## Usage with Fiber

```go
client, err := oidcauth.New(oidcauth.Config{
	Issuer:       "https://id.example.com",
	ClientID:     os.Getenv("AUTH_OIDC_CLIENT_ID"),
	ClientSecret: os.Getenv("AUTH_OIDC_CLIENT_SECRET"),
	RedirectURL:  "https://app.example.com/api/v1/auth/oidc/callback",
	CookieSecret: os.Getenv("AUTH_OIDC_COOKIE_SECRET"), // >= 32 chars
	CookiePath:   "/api/v1/auth/oidc",
})

tickets := oidcauth.NewMemoryTicketStore() // use Redis GETDEL with replicas

h := oidcfiber.New(client, oidcfiber.Options{
	OnSuccess: func(c *fiber.Ctx, res *oidcauth.Result) error {
		// App policy: link by (iss, sub), else match a local user by verified email.
		user, err := users.FromOIDC(c.UserContext(), res.Identity)
		if err != nil {
			return c.Redirect("/auth/login?error=not_allowed")
		}
		token, _ := sessions.Issue(user)
		ticket, _ := tickets.Put(c.UserContext(), token, time.Minute)
		return c.Redirect("/auth/callback?ticket=" + url.QueryEscape(ticket) +
			"&redirect=" + url.QueryEscape(oidcauth.SafeReturnTo(res.ReturnTo, "/")))
	},
	OnError: func(c *fiber.Ctx, err error) error {
		return c.Redirect("/auth/login?error=oidc_failed")
	},
})

app.Get("/api/v1/auth/oidc/login", h.Login)       // ?redirect=/path
app.Get("/api/v1/auth/oidc/callback", h.Callback) // register this as redirect URI
// The SPA then POSTs the ticket to an endpoint that calls tickets.Take.
```

The adapter is optional. `Client.Start` and `Client.Finish` work with any
framework: set the returned cookie, redirect, then pass the callback query
and the cookie value back in.

## Linking identities

Store `(Identity.Issuer, Identity.Subject)` as the unique key of an external
identity. Match by `Email` only when `EmailVerified` is true, and only for
providers you trust to verify email.

## Zitadel notes

- Roles arrive in `urn:zitadel:iam:org:project:roles` once the project has
  **"Assert Roles on Authentication"** enabled. Turn on **"Check authorization
  on Authentication"** to block users without a grant.
- To pin login to one organization, use
  `oidcauth.WithExtraScopes("urn:zitadel:iam:org:id:<orgId>")`.

## Testing

```go
op := oidctest.NewProvider(t, "client", "secret")
client, _ := oidcauth.New(oidcauth.Config{Issuer: op.Issuer(), ClientID: "client", ...})
authURL, cookie, _ := client.Start(ctx)
query := op.Authorize(t, authURL, oidctest.User{Subject: "u1", Email: "u1@example.com", EmailVerified: true})
res, err := client.Finish(ctx, query, cookie.Value)
```

## License

MIT
