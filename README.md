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
- **ID tokens from native apps** (`VerifyIDToken`): a mobile app logs in
  itself (or with Sign in with Apple) and the backend verifies its ID token.
- Client authentication: `client_secret_basic`, `client_secret_post`,
  `private_key_jwt` and `none` (public client + PKCE).
- A **Fiber v2 adapter** (`oidcfiber`) and an in-process **fake provider**
  (`oidctest`) for end-to-end tests.

The core packages (`oidcauth`, `oidcfiber`, `oidctest`) work with any OpenID
Connect provider: Zitadel, Keycloak, Google, Microsoft Entra ID, Auth0,
Authentik, and others. The only Zitadel-aware default is the roles claim,
and `RoleExtractor` overrides it. The optional `zitadel` packages (see
[Zitadel identity provider login](#zitadel-identity-provider-login-without-zitadels-pages))
are Zitadel-only.

`oidcauth` deliberately does **not** do the following. Each application
decides them:

- Create, link or reject local users. The app receives an `Identity` and does
  whatever its policy says.
- Issue sessions or JWTs. Keep using your existing token and middleware.

## Install

```bash
go get github.com/vuongtlt13/oidcauth
```

## Documentation

Step-by-step guides (Vietnamese) are in [`docs/`](docs/README.md):

- [Setup](docs/setup.md): wiring, `Config` ↔ environment variables,
  `TicketStore`, cookies, local development, production checklist.
- [Zitadel](docs/zitadel/README.md): web application (secret, Private Key
  JWT, PKCE), roles and organizations, Google through Zitadel with or without
  Zitadel's pages, logout and account linking, troubleshooting.
- [Other providers](docs/providers.md): Google direct, Keycloak, Microsoft
  Entra ID, Auth0.

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
| OIDC Core §3.1.3.7 for tokens obtained elsewhere | `VerifyIDToken` (`aud` of another client, `nonce`, max age, `at_hash`) |
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

## ID tokens from native apps

A mobile or desktop app logs in itself (authorization code + PKCE in the
system browser, as a public client, or Sign in with Apple) and sends its ID
token to the backend, which verifies it and issues its own session:

```go
identity, err := client.VerifyIDToken(ctx, idToken,
	oidcauth.WithAccessToken(accessToken),   // optional: checks at_hash, merges userinfo
	oidcauth.WithAudience("native-app-client"), // the app's client id; default Config.ClientID
	oidcauth.WithNonce(nonce),               // optional: when the app sends its nonce
	oidcauth.WithTokenMaxAge(5*time.Minute), // optional: refuse older tokens (now - iat)
)
```

It checks the signature, `iss`, `aud`, `azp`, `exp` and `iat` like a browser
login; an invalid token is an `IsUserError`. The app's client may belong to
another project of the same provider: only the issuer must match. An ID
token is a bearer proof of the login, so keep the max age short and the
transport on HTTPS.

A provider used only this way needs no redirect URL or cookie secret: set
`VerifyOnly`. For Sign in with Apple:

```go
apple, _ := oidcauth.New(oidcauth.Config{
	Issuer:     "https://appleid.apple.com",
	ClientID:   "com.example.app", // the bundle id, the `aud` of the token
	VerifyOnly: true,              // Start/Finish return ErrVerifyOnly
})
identity, err := apple.VerifyIDToken(ctx, credential.IdentityToken, oidcauth.WithTokenMaxAge(10*time.Minute))
```

Apple sends the name only to the app, at the first authorization: have the
app pass it along.

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
  **"Return user roles during authentication"** enabled. Turn on **"Only
  authorized users can authenticate"** to block users without a role
  assignment.
- To pin login to one organization, use
  `oidcauth.WithExtraScopes("urn:zitadel:iam:org:id:<orgId>")`.

## Zitadel identity provider login without Zitadel's pages

The `zitadel` and `zitadel/zitadelfiber` packages are optional and
**Zitadel-only**. With them, a "Sign in with Google" button can log in to
Zitadel without Zitadel's login UI: the browser only sees Google's page. The
app plays Zitadel's login UI through the v2 API, the way Login V2 does.

```text
GET  /auth/google/login                  zitadelfiber.Handler.Login
     server side: authorize (not followed) → auth request V2_…
                  POST /v2/idp_intents → Google URL
  → Google → Zitadel /idps/callback
  → GET /auth/google/idp/callback?rq=…   zitadelfiber.Handler.Callback
     RetrieveIntent → find / auto-link / auto-create the user
     POST /v2/sessions → POST /v2/oidc/auth_requests/{id}
  → GET <RedirectURL>?code=…             oidcfiber.Handler.Callback (state, nonce, PKCE)
```

The result is a regular Zitadel login of the same client: same issuer,
subject, roles and back-channel logout.

```go
api := zitadel.New(client.Config().Issuer, os.Getenv("ZITADEL_SERVICE_PAT"), nil)
idp := zitadelfiber.New(client, zitadel.NewIDPLogin(api, googleIDPID), zitadelfiber.Options{
	Tickets:     tickets, // the same TicketStore as the login tickets is fine
	CallbackURL: "https://api.example.com/auth/google/idp/callback",
	LoginOptions: func(c *fiber.Ctx) []oidcauth.LoginOption {
		return []oidcauth.LoginOption{oidcauth.WithExtraScopes("urn:zitadel:iam:org:id:" + orgID)}
	},
	OnError: func(c *fiber.Ctx, err error) error {
		switch {
		case errors.Is(err, zitadel.ErrNotLinked): // no user, no auto-link/creation
		case errors.Is(err, zitadel.ErrMFARequired): // org forces MFA for external logins
		}
		return c.Redirect("/login?error=...")
	},
})
app.Get("/auth/google/login", idp.Login)
app.Get("/auth/google/idp/callback", idp.Callback)
// The code still arrives at the client's callback (oidcfiber), with OnSuccess as usual.
```

- **Service user**: a Zitadel service user with the *instance* role
  `IAM_LOGIN_CLIENT` and a personal access token.
- **Who can log in** follows the IdP options in Zitadel:
  - an already linked account;
  - *auto-linking* by verified email (exactly one matching user) or by
    username, if the user's org allows external IdPs and offers this IdP for
    linking;
  - *auto-creation* (a missing given or family name takes the other one, the
    display name or the email's local part) into the org of the
    `urn:zitadel:iam:org:id:` scope, or else the default org.
- **Errors** (`errors.Is`):

  | Error | Meaning |
  |---|---|
  | `ErrNotLinked` | no user found or created |
  | `ErrNotAllowed` | wrong org, or the org does not offer the IdP |
  | `ErrAccessDenied` | no project grant |
  | `ErrUserInactive` | user deactivated or locked |
  | `ErrMFARequired` | org forces MFA for external logins |
  | `ErrAuthRequestExpired` | auth request expired or already handled |
  | `ErrIntentFailed` | cancelled at the IdP |
  | `oidcauth.ErrInvalidState` | unknown or used ticket |
  | `*zitadel.APIError` | other API failures |

  `zitadel.IsUserError` separates refusals from an unavailable Zitadel.
- **Why server-side authorize**: with `LoginV2.Required` on the instance,
  Zitadel ignores the per-app Login V2 base URI, so the app cannot be
  registered as the login UI.
- `zitadeltest` is a fake of the v2 API on top of `oidctest`, for end-to-end
  tests.

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
