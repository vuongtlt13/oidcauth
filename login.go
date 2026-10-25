package oidcauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

// Response modes usable by a server-side relying party. `fragment` is not:
// the fragment never reaches the server.
const (
	ResponseModeQuery    = "query"
	ResponseModeFormPost = "form_post"
)

// LoginOption customises one authorization request
// (OpenID Connect Core 1.0, section 3.1.2.1).
type LoginOption func(*loginOptions)

type loginOptions struct {
	returnTo      string
	scopes        []string
	extraScopes   []string
	prompt        []string
	loginHint     string
	idTokenHint   string
	maxAge        *time.Duration
	acrValues     []string
	uiLocales     []string
	claimsLocales []string
	display       string
	responseMode  string
	claims        *ClaimsRequest
	params        map[string]string
}

// WithReturnTo stores an application value (usually a relative path to go back
// to) in the flow cookie; it is handed back by Finish. Sanitize it with
// SafeReturnTo before redirecting.
func WithReturnTo(v string) LoginOption { return func(o *loginOptions) { o.returnTo = v } }

// WithScopes replaces Config.Scopes for this request. ScopeOpenID is added
// when missing.
func WithScopes(s ...string) LoginOption {
	return func(o *loginOptions) { o.scopes = append([]string(nil), s...) }
}

// WithExtraScopes appends scopes for this request only, e.g. ScopePhone, or
// the Zitadel `urn:zitadel:iam:org:id:<org>` scope to pin the login to one
// organization.
func WithExtraScopes(s ...string) LoginOption {
	return func(o *loginOptions) { o.extraScopes = append(o.extraScopes, s...) }
}

// WithPrompt sets `prompt`: PromptNone, PromptLogin, PromptConsent,
// PromptSelectAccount, PromptCreate (space-separated when several).
func WithPrompt(p ...string) LoginOption { return func(o *loginOptions) { o.prompt = p } }

// WithLoginHint pre-fills the provider login form (`login_hint`).
func WithLoginHint(hint string) LoginOption { return func(o *loginOptions) { o.loginHint = hint } }

// WithIDTokenHint passes a previously issued ID token as `id_token_hint`,
// typically together with PromptNone for a silent re-authentication.
func WithIDTokenHint(idToken string) LoginOption {
	return func(o *loginOptions) { o.idTokenHint = idToken }
}

// WithMaxAge sets `max_age`: the provider must re-authenticate the user when
// the last authentication is older than d. Finish then requires `auth_time`
// in the ID token and checks it. WithMaxAge(0) forces re-authentication, like
// PromptLogin, but verifiably.
func WithMaxAge(d time.Duration) LoginOption {
	return func(o *loginOptions) { o.maxAge = &d }
}

// WithACRValues sets `acr_values` (requested authentication context classes,
// in order of preference). With Config.RequireACR the ID token `acr` must be
// one of them.
func WithACRValues(v ...string) LoginOption { return func(o *loginOptions) { o.acrValues = v } }

// WithUILocales sets `ui_locales` (BCP47 tags, preferred first) for the
// provider pages.
func WithUILocales(l ...string) LoginOption { return func(o *loginOptions) { o.uiLocales = l } }

// WithClaimsLocales sets `claims_locales` for the returned claims.
func WithClaimsLocales(l ...string) LoginOption {
	return func(o *loginOptions) { o.claimsLocales = l }
}

// WithDisplay sets `display`: DisplayPage, DisplayPopup, DisplayTouch or
// DisplayWAP.
func WithDisplay(d string) LoginOption { return func(o *loginOptions) { o.display = d } }

// WithResponseMode sets `response_mode`: ResponseModeQuery (default for the
// code flow) or ResponseModeFormPost. form_post makes the provider POST the
// callback; the flow cookie of that login is then SameSite=None (a Lax cookie
// is not sent on a cross-site POST), which needs HTTPS.
func WithResponseMode(m string) LoginOption { return func(o *loginOptions) { o.responseMode = m } }

// WithClaims sets the `claims` request parameter (section 5.5).
func WithClaims(r *ClaimsRequest) LoginOption { return func(o *loginOptions) { o.claims = r } }

// WithParam adds a custom authorization request parameter. Parameters the
// library controls (state, nonce, PKCE, client_id, redirect_uri,
// response_type, scope, ...) cannot be set this way; Start returns an error.
func WithParam(key, value string) LoginOption {
	return func(o *loginOptions) {
		if o.params == nil {
			o.params = map[string]string{}
		}
		o.params[key] = value
	}
}

// reservedParams have a dedicated option or must not be set by the caller.
var reservedParams = map[string]struct{}{
	"client_id": {}, "redirect_uri": {}, "response_type": {}, "state": {}, "nonce": {},
	"code_challenge": {}, "code_challenge_method": {}, "scope": {}, "prompt": {},
	"max_age": {}, "acr_values": {}, "id_token_hint": {}, "login_hint": {},
	"ui_locales": {}, "claims_locales": {}, "display": {}, "response_mode": {},
	"claims": {}, "request": {}, "request_uri": {},
}

// requestedScopes is Config.Scopes, or the WithScopes override, plus extra
// scopes, de-duplicated with openid first.
func (c *Client) requestedScopes(o *loginOptions) []string {
	base := c.cfg.Scopes
	if o.scopes != nil {
		base = o.scopes
	}
	out := []string{ScopeOpenID}
	for _, s := range append(append([]string(nil), base...), o.extraScopes...) {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// Start begins a login. The caller must set the returned cookie on the
// response and redirect the browser to authURL.
func (c *Client) Start(ctx context.Context, opts ...LoginOption) (authURL string, cookie *http.Cookie, err error) {
	var o loginOptions
	for _, opt := range opts {
		opt(&o)
	}
	for k := range o.params {
		if _, ok := reservedParams[k]; ok {
			return "", nil, fmt.Errorf("oidcauth: parameter %q cannot be set with WithParam", k)
		}
	}
	switch o.responseMode {
	case "", ResponseModeQuery, ResponseModeFormPost:
	default:
		return "", nil, fmt.Errorf("oidcauth: unsupported response_mode %q", o.responseMode)
	}
	if o.maxAge == nil && c.cfg.MaxAge > 0 {
		o.maxAge = &c.cfg.MaxAge
	}
	if o.maxAge != nil && *o.maxAge < 0 {
		return "", nil, errors.New("oidcauth: max_age must not be negative")
	}
	if o.acrValues == nil {
		o.acrValues = c.cfg.ACRValues
	}

	party, err := c.relyingParty(ctx)
	if err != nil {
		return "", nil, err
	}

	scopes := c.requestedScopes(&o)
	f := flow{
		State:    randomToken(),
		Nonce:    randomToken(),
		Verifier: oauth2.GenerateVerifier(),
		ReturnTo: o.returnTo,
		Scope:    strings.Join(scopes, " "),
		IssuedAt: c.flows.now().Unix(),
	}
	if o.maxAge != nil {
		secs := int64(o.maxAge.Round(time.Second) / time.Second)
		f.MaxAge = &secs
	}
	if c.cfg.RequireACR {
		f.ACR = o.acrValues
	}
	cookie, err = c.flows.encode(f, o.responseMode == ResponseModeFormPost)
	if err != nil {
		return "", nil, err
	}

	params := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", f.Nonce),
		oauth2.SetAuthURLParam("scope", f.Scope),
	}
	set := func(key, value string) {
		if value != "" {
			params = append(params, oauth2.SetAuthURLParam(key, value))
		}
	}
	set("prompt", strings.Join(o.prompt, " "))
	set("login_hint", o.loginHint)
	set("id_token_hint", o.idTokenHint)
	if f.MaxAge != nil {
		set("max_age", strconv.FormatInt(*f.MaxAge, 10))
	}
	set("acr_values", strings.Join(o.acrValues, " "))
	set("ui_locales", strings.Join(o.uiLocales, " "))
	set("claims_locales", strings.Join(o.claimsLocales, " "))
	set("display", o.display)
	set("response_mode", o.responseMode)
	if o.claims != nil {
		raw, err := json.Marshal(o.claims)
		if err != nil {
			return "", nil, fmt.Errorf("oidcauth: encode claims request: %w", err)
		}
		set("claims", string(raw))
	}
	for k, v := range o.params {
		set(k, v)
	}
	authURL = rp.AuthURL(f.State, party,
		rp.WithCodeChallenge(oidc.NewSHACodeChallenge(f.Verifier)),
		func() []oauth2.AuthCodeOption { return params },
	)
	return authURL, cookie, nil
}

// Result is a verified login.
type Result struct {
	Identity *Identity
	// ReturnTo is the value passed with WithReturnTo, unsanitized.
	ReturnTo string
}

// Finish completes a login from the callback parameters (the query, or the
// form body with ResponseModeFormPost) and the flow cookie value (looked up
// with CookieNameFor(params.Get("state"))). The caller must always set
// ClearCookie(state) on the response, whatever the outcome.
//
// It verifies state, exchanges the code with the PKCE verifier, validates the
// ID token (signature via JWKS, iss, aud, azp, exp, iat, nonce, at_hash),
// checks auth_time when max_age was requested and acr when Config.RequireACR
// is set, and, unless SkipUserInfo is set, merges userinfo claims.
func (c *Client) Finish(ctx context.Context, params url.Values, cookieValue string) (*Result, error) {
	state := params.Get("state")
	if state == "" || cookieValue == "" {
		return nil, ErrInvalidState
	}
	f, err := c.flows.decode(state, cookieValue)
	if err != nil {
		return nil, err
	}
	if iss := params.Get("iss"); iss != "" && iss != c.cfg.Issuer {
		// RFC 9207 authorization server issuer identification: a response
		// from another issuer is a mix-up attack.
		return nil, &tokenError{op: "authorization response", err: fmt.Errorf("iss %q does not match issuer", iss)}
	}
	if code := params.Get("error"); code != "" {
		return nil, &ProviderError{Code: code, Description: params.Get("error_description")}
	}
	code := params.Get("code")
	if code == "" {
		return nil, ErrMissingCode
	}

	party, err := c.relyingParty(ctx)
	if err != nil {
		return nil, err
	}
	exchangeOpts, err := c.clientAssertion(party)
	if err != nil {
		return nil, err
	}
	exchangeOpts = append(exchangeOpts, rp.WithCodeVerifier(f.Verifier))
	ctx = context.WithValue(ctx, nonceKey{}, f.Nonce)
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, party, exchangeOpts...)
	if err != nil {
		return nil, classify("code exchange", err)
	}
	if err := c.checkAuthContext(f, tokens.IDTokenClaims); err != nil {
		return nil, &tokenError{op: "code exchange", err: err}
	}

	identity, err := c.identityFromTokens(ctx, party, tokens.IDToken, tokens.IDTokenClaims.GetSubject(), tokens.Token)
	if err != nil {
		return nil, err
	}
	identity.Tokens = tokensFrom(tokens.Token, tokens.IDToken, f.Scope)
	return &Result{Identity: identity, ReturnTo: f.ReturnTo}, nil
}

// authTimeSkew tolerates clock differences between the provider and the app
// when checking auth_time against max_age.
const authTimeSkew = 30 * time.Second

// checkAuthContext enforces max_age (section 3.1.2.1: auth_time is then
// REQUIRED) and the requested acr values.
func (c *Client) checkAuthContext(f *flow, claims *oidc.IDTokenClaims) error {
	if f.MaxAge != nil {
		authTime := claims.GetAuthTime()
		if authTime.IsZero() {
			return oidc.ErrAuthTimeNotPresent
		}
		// Measured from when the login started, so max_age=0 means "the user
		// authenticated during this login".
		oldest := time.Unix(f.IssuedAt, 0).Add(-time.Duration(*f.MaxAge)*time.Second - authTimeSkew)
		if authTime.Before(oldest) {
			return fmt.Errorf("%w: auth_time %s is older than max_age %ds", oidc.ErrAuthTimeToOld, authTime.UTC().Format(time.RFC3339), *f.MaxAge)
		}
	}
	if len(f.ACR) > 0 {
		if acr := claims.GetAuthenticationContextClassReference(); !slices.Contains(f.ACR, acr) {
			return fmt.Errorf("%w: got %q, want one of %v", oidc.ErrAcrInvalid, acr, f.ACR)
		}
	}
	return nil
}

// identityFromTokens builds the Identity from the verified ID token merged
// with userinfo.
func (c *Client) identityFromTokens(ctx context.Context, party rp.RelyingParty, idToken, subject string, token *oauth2.Token) (*Identity, error) {
	claims, err := jwtPayload(idToken)
	if err != nil {
		return nil, err
	}
	if !c.cfg.SkipUserInfo && party.UserinfoEndpoint() != "" {
		info, err := rp.Userinfo[*oidc.UserInfo](ctx, token.AccessToken, token.Type(), subject, party)
		if err != nil {
			return nil, fmt.Errorf("oidcauth: userinfo failed: %w", err)
		}
		if err := mergeUserInfo(claims, info); err != nil {
			return nil, err
		}
	}
	return identityFromClaims(claims, c.cfg.RoleExtractor), nil
}

// CookieNameFor returns the flow cookie name for a callback state.
func (c *Client) CookieNameFor(state string) string { return c.flows.name(state) }

// ClearCookie returns a cookie that deletes the flow cookie of state.
func (c *Client) ClearCookie(state string) *http.Cookie { return c.flows.clear(state) }
