// Package oidcauth is a thin, framework-agnostic OpenID Connect relying party
// for browser login (Authorization Code flow + PKCE + state + nonce), built on
// github.com/zitadel/oidc/v3 (OpenID certified).
//
// The library verifies the provider response and returns an Identity. It does
// not touch your user table and does not issue session tokens: what to do with
// the identity (link, provision, reject) and how to keep the user signed in is
// the application's decision.
//
// See the fiber sub-package for a ready-made Fiber adapter.
package oidcauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

var (
	// ErrInvalidState means the callback did not match a login flow started by
	// this browser (missing/expired/tampered flow cookie, or state mismatch).
	ErrInvalidState = errors.New("oidcauth: invalid or expired login state")
	// ErrMissingCode means the callback carries neither a code nor an error.
	ErrMissingCode = errors.New("oidcauth: authorization code missing")
)

// ProviderError is an error returned by the provider at the callback
// (`error`/`error_description` parameters), e.g. access_denied when the user
// has no grant for the project.
type ProviderError struct {
	Code        string
	Description string
}

func (e *ProviderError) Error() string {
	if e.Description == "" {
		return "oidcauth: provider error: " + e.Code
	}
	return fmt.Sprintf("oidcauth: provider error: %s: %s", e.Code, e.Description)
}

// IsUserError reports whether err is caused by the browser/user side of the
// flow (bad or expired state, provider-reported error such as access_denied,
// missing code, rejected code or token) rather than the provider being
// unreachable. Handlers typically map it to 401 versus 502.
func IsUserError(err error) bool {
	var pe *ProviderError
	var ce *exchangeError
	return errors.Is(err, ErrInvalidState) || errors.Is(err, ErrMissingCode) ||
		errors.As(err, &pe) || errors.As(err, &ce)
}

// exchangeError wraps a rejected code exchange or invalid ID token.
type exchangeError struct{ err error }

func (e *exchangeError) Error() string { return "oidcauth: code exchange failed: " + e.err.Error() }
func (e *exchangeError) Unwrap() error { return e.err }

// Client is safe for concurrent use. Provider discovery happens lazily on the
// first login (and is retried until it succeeds), so an unreachable provider
// never prevents the application from starting; local login keeps working.
type Client struct {
	cfg   Config
	flows *flowCodec

	mu sync.Mutex
	rp rp.RelyingParty
}

type nonceKey struct{}

// New validates cfg and returns a Client. It does not contact the provider.
func New(cfg Config) (*Client, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("oidcauth: %w", err)
	}
	return &Client{cfg: cfg, flows: newFlowCodec(cfg)}, nil
}

// Config returns the effective configuration (with defaults applied).
func (c *Client) Config() Config { return c.cfg }

// Init eagerly runs provider discovery. Optional: useful as a readiness check.
func (c *Client) Init(ctx context.Context) error {
	_, err := c.relyingParty(ctx)
	return err
}

func (c *Client) relyingParty(ctx context.Context) (rp.RelyingParty, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rp != nil {
		return c.rp, nil
	}
	party, err := rp.NewRelyingPartyOIDC(ctx,
		c.cfg.Issuer, c.cfg.ClientID, c.cfg.ClientSecret, c.cfg.RedirectURL, c.cfg.Scopes,
		rp.WithHTTPClient(c.cfg.HTTPClient),
		rp.WithVerifierOpts(rp.WithNonce(func(ctx context.Context) string {
			nonce, _ := ctx.Value(nonceKey{}).(string)
			return nonce
		})),
		rp.WithSigningAlgsFromDiscovery(),
	)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: provider discovery failed: %w", err)
	}
	c.rp = party
	return party, nil
}

// LoginOption customises one authorization request.
type LoginOption func(*loginOptions)

type loginOptions struct {
	returnTo    string
	prompt      []string
	loginHint   string
	extraScopes []string
	params      map[string]string
}

// WithReturnTo stores an application value (usually a relative path to go back
// to) in the flow cookie; it is handed back by Finish. Sanitize it with
// SafeReturnTo before redirecting.
func WithReturnTo(v string) LoginOption { return func(o *loginOptions) { o.returnTo = v } }

// WithPrompt sets `prompt` (e.g. "login", "select_account", "create").
func WithPrompt(p ...string) LoginOption { return func(o *loginOptions) { o.prompt = p } }

// WithLoginHint pre-fills the provider login form.
func WithLoginHint(hint string) LoginOption { return func(o *loginOptions) { o.loginHint = hint } }

// WithExtraScopes appends scopes for this request only, e.g. the Zitadel
// `urn:zitadel:iam:org:id:<org>` scope to pin the login to one organization.
func WithExtraScopes(s ...string) LoginOption {
	return func(o *loginOptions) { o.extraScopes = append(o.extraScopes, s...) }
}

// WithParam adds a custom authorization request parameter.
func WithParam(key, value string) LoginOption {
	return func(o *loginOptions) {
		if o.params == nil {
			o.params = map[string]string{}
		}
		o.params[key] = value
	}
}

// Start begins a login. The caller must set the returned cookie on the
// response and redirect the browser to authURL.
func (c *Client) Start(ctx context.Context, opts ...LoginOption) (authURL string, cookie *http.Cookie, err error) {
	party, err := c.relyingParty(ctx)
	if err != nil {
		return "", nil, err
	}
	var o loginOptions
	for _, opt := range opts {
		opt(&o)
	}

	f := flow{
		State:    randomToken(),
		Nonce:    randomToken(),
		Verifier: oauth2.GenerateVerifier(),
		ReturnTo: o.returnTo,
	}
	cookie, err = c.flows.encode(f)
	if err != nil {
		return "", nil, err
	}

	params := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", f.Nonce)}
	if len(o.prompt) > 0 {
		params = append(params, oauth2.SetAuthURLParam("prompt", strings.Join(o.prompt, " ")))
	}
	if o.loginHint != "" {
		params = append(params, oauth2.SetAuthURLParam("login_hint", o.loginHint))
	}
	if len(o.extraScopes) > 0 {
		scopes := append(append([]string(nil), c.cfg.Scopes...), o.extraScopes...)
		params = append(params, oauth2.SetAuthURLParam("scope", strings.Join(scopes, " ")))
	}
	for k, v := range o.params {
		params = append(params, oauth2.SetAuthURLParam(k, v))
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

// Finish completes a login from the callback query and the flow cookie value
// (looked up with CookieNameFor(query.Get("state"))). The caller must always
// set ClearCookie(state) on the response, whatever the outcome.
//
// It verifies state, exchanges the code with the PKCE verifier, validates the
// ID token (signature via JWKS, iss, aud, azp, exp, iat, nonce, at_hash) and,
// unless SkipUserInfo is set, merges userinfo claims.
func (c *Client) Finish(ctx context.Context, query url.Values, cookieValue string) (*Result, error) {
	state := query.Get("state")
	if state == "" || cookieValue == "" {
		return nil, ErrInvalidState
	}
	f, err := c.flows.decode(state, cookieValue)
	if err != nil {
		return nil, err
	}
	if code := query.Get("error"); code != "" {
		return nil, &ProviderError{Code: code, Description: query.Get("error_description")}
	}
	code := query.Get("code")
	if code == "" {
		return nil, ErrMissingCode
	}

	party, err := c.relyingParty(ctx)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, nonceKey{}, f.Nonce)
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, party, rp.WithCodeVerifier(f.Verifier))
	if err != nil {
		var netErr *url.Error
		if errors.As(err, &netErr) {
			return nil, fmt.Errorf("oidcauth: token endpoint unreachable: %w", err)
		}
		return nil, &exchangeError{err: err}
	}

	claims, err := jwtPayload(tokens.IDToken)
	if err != nil {
		return nil, err
	}
	if !c.cfg.SkipUserInfo && party.UserinfoEndpoint() != "" {
		info, err := rp.Userinfo[*oidc.UserInfo](ctx, tokens.AccessToken, tokens.TokenType, tokens.IDTokenClaims.GetSubject(), party)
		if err != nil {
			return nil, fmt.Errorf("oidcauth: userinfo failed: %w", err)
		}
		if err := mergeUserInfo(claims, info); err != nil {
			return nil, err
		}
	}

	identity := identityFromClaims(claims, c.cfg.RoleExtractor)
	identity.Tokens = Tokens{
		IDToken:      tokens.IDToken,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		Expiry:       tokens.Expiry,
	}
	return &Result{Identity: identity, ReturnTo: f.ReturnTo}, nil
}

// CookieNameFor returns the flow cookie name for a callback state.
func (c *Client) CookieNameFor(state string) string { return c.flows.name(state) }

// ClearCookie returns a cookie that deletes the flow cookie of state.
func (c *Client) ClearCookie(state string) *http.Cookie { return c.flows.clear(state) }

// LogoutURL builds the RP-initiated logout URL (end_session_endpoint). It
// returns "" when the provider does not advertise one. postLogoutRedirect must
// be registered at the provider; empty uses Config.PostLogoutRedirectURL.
func (c *Client) LogoutURL(ctx context.Context, idTokenHint, postLogoutRedirect, state string) (string, error) {
	party, err := c.relyingParty(ctx)
	if err != nil {
		return "", err
	}
	endpoint := party.GetEndSessionEndpoint()
	if endpoint == "" {
		return "", nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("oidcauth: invalid end_session_endpoint: %w", err)
	}
	q := u.Query()
	q.Set("client_id", c.cfg.ClientID)
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirect == "" {
		postLogoutRedirect = c.cfg.PostLogoutRedirectURL
	}
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// jwtPayload decodes the claims of an already verified JWT.
func jwtPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidcauth: malformed id_token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidcauth: malformed id_token payload: %w", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("oidcauth: malformed id_token payload: %w", err)
	}
	return claims, nil
}

// protectedClaims come from the verified ID token and are never overridden by
// userinfo.
var protectedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "azp": {}, "exp": {}, "iat": {}, "nbf": {},
	"nonce": {}, "auth_time": {}, "at_hash": {}, "c_hash": {}, "sid": {}, "jti": {},
}

func mergeUserInfo(claims map[string]any, info *oidc.UserInfo) error {
	raw, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("oidcauth: encode userinfo: %w", err)
	}
	extra := map[string]any{}
	if err := json.Unmarshal(raw, &extra); err != nil {
		return fmt.Errorf("oidcauth: decode userinfo: %w", err)
	}
	for k, v := range extra {
		if _, ok := protectedClaims[k]; ok {
			continue
		}
		claims[k] = v
	}
	return nil
}
