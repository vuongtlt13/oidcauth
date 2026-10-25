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
- **Scopes and standard claims**: `openid`, `profile`, `email`, `phone`,
  `address` and `offline_access`, with every standard claim mapped. The
  scopes the provider actually granted are reported in `Tokens.Scopes`.
- All authorization request parameters: `prompt`, `login_hint`,
  `id_token_hint`, `max_age` (with an `auth_time` check), `acr_values` (with
  an optional `acr` check), `ui_locales`, `claims_locales`, `display`,
  `response_mode` (`query` / `form_post`), `claims` and custom parameters.
- **Refresh** (`refresh_token` grant), **revocation** (RFC 7009) and
  **userinfo**.
- RP-initiated logout (`LogoutURL`) and **back-channel logout** token
  verification (`VerifyLogoutToken`).
- Client authentication: `client_secret_basic`, `client_secret_post`,
  `private_key_jwt` and `none` (public client + PKCE).
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
// app.Post("/api/v1/auth/oidc/callback", h.Callback) // also, with response_mode=form_post
// The SPA then POSTs the ticket to an endpoint that calls tickets.Take.
```

The adapter is optional. `Client.Start` and `Client.Finish` work with any
framework: set the returned cookie, redirect, then pass the callback query
and the cookie value back in.

## Standards coverage

| Specification | Supported |
|---|---|
| OpenID Connect Core 1.0, Authorization Code flow | yes. Implicit and hybrid flows are intentionally not supported |
| RFC 7636 PKCE | S256, always on |
| OIDC Core §3.1.2.1 request parameters | `scope`, `prompt`, `login_hint`, `id_token_hint`, `max_age`, `acr_values`, `ui_locales`, `claims_locales`, `display`, `response_mode`, `claims` |
| OIDC Core §3.1.3.7 ID token validation | signature (JWKS, algs from discovery), `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`, `at_hash`, plus `auth_time` with `max_age` and `acr` with `RequireACR` |
| OIDC Core §5.1 standard claims, §5.4 scope claims, §5.5 claims request | yes |
| OIDC Core §5.3 UserInfo | merged at login (`SkipUserInfo` disables it); `sub` must match the ID token |
| OIDC Core §9 client authentication | `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none` |
| OIDC Core §12 refresh tokens | `Refresh`; the refreshed ID token is verified |
| OAuth 2.0 Form Post Response Mode | `WithResponseMode(ResponseModeFormPost)` |
| RFC 9207 `iss` authorization response parameter | checked when present |
| RFC 7009 token revocation | `Revoke` |
| OIDC Discovery 1.0 | yes; `DiscoveryURL` overrides the URL; `Discovery()` returns the metadata |
| OIDC RP-Initiated Logout 1.0 | `LogoutURL` (`id_token_hint`, `logout_hint`, `ui_locales`, `state`) |
| OIDC Back-Channel Logout 1.0 | `VerifyLogoutToken`, `oidcfiber.Handler.BackChannelLogout` |

## Scopes and claims

The default scopes are `openid profile email`. Change them for every login
with `Config.Scopes`, or for one login with `WithScopes` / `WithExtraScopes`:

| Scope | `Identity` fields |
|---|---|
| `openid` (always sent) | `Issuer`, `Subject`, `AuthTime`, `ACR`, `AMR`, `SessionID` |
| `profile` | `Name`, `GivenName`, `FamilyName`, `MiddleName`, `Nickname`, `PreferredUsername`, `Profile`, `Picture`, `Website`, `Gender`, `Birthdate`, `Zoneinfo`, `Locale`, `UpdatedAt` |
| `email` | `Email`, `EmailVerified` |
| `phone` | `PhoneNumber`, `PhoneNumberVerified` |
| `address` | `Address` |
| `offline_access` | `Tokens.RefreshToken` |

A provider may grant fewer scopes than requested. Check the result with
`Identity.Tokens.HasScope(oidcauth.ScopeEmail)`. All claims, standard or not,
are available in `Identity.Claims`.

```go
authURL, cookie, err := client.Start(ctx,
	oidcauth.WithExtraScopes(oidcauth.ScopePhone, oidcauth.ScopeOfflineAccess),
	oidcauth.WithPrompt(oidcauth.PromptSelectAccount),
	oidcauth.WithUILocales("vi", "en"),
	oidcauth.WithMaxAge(15*time.Minute), // re-authenticate if older; auth_time is checked
)
```

## Refresh, revoke, userinfo

```go
res, err := client.Refresh(ctx, identity.Tokens.RefreshToken) // res.Identity is nil without an ID token
err = client.Revoke(ctx, refreshToken, oidcauth.TokenTypeHintRefreshToken)
claims, err := client.UserInfo(ctx, accessToken, identity.Subject)
```

Most apps do not need these. They are for apps that call provider APIs on
behalf of the user, or that want to tie their own session lifetime to the
provider grant.

## Logout

```go
// RP-initiated: redirect the browser here after clearing the app session.
u, err := client.LogoutURL(ctx, idToken, "https://app.example.com/", "")

// Back-channel: register https://app.example.com/api/v1/auth/oidc/backchannel-logout at the provider.
app.Post("/api/v1/auth/oidc/backchannel-logout", h.BackChannelLogout(
	func(c *fiber.Ctx, t *oidcauth.LogoutToken) error {
		// End app sessions of t.Subject (all) or t.SessionID (Identity.SessionID at login).
		// Reject a t.JWTID seen before t.Expiry to stop replays.
		return sessions.EndProvider(c.UserContext(), t.Subject, t.SessionID)
	}))
```

## Client authentication

| Config | Method |
|---|---|
| `ClientSecret` | `client_secret_basic`. Set `TokenEndpointAuthMethod: AuthMethodClientSecretPost` for `client_secret_post` |
| `ClientKey` + `ClientKeyID` (PEM; Zitadel app key JSON `key` / `keyId`) | `private_key_jwt` |
| neither | `none`: a public client, protected by PKCE |

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
