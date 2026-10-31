// Package oidcauth is a thin, framework-agnostic OpenID Connect relying party
// for browser login (Authorization Code flow + PKCE + state + nonce), built on
// github.com/zitadel/oidc/v3 (OpenID certified).
//
// The library verifies the provider response and returns an Identity. It does
// not touch your user table and does not issue session tokens: what to do with
// the identity (link, provision, reject) and how to keep the user signed in is
// the application's decision.
//
// See the oidcfiber sub-package for a ready-made Fiber adapter.
package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
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
	// ErrNotSupported means the provider does not advertise the endpoint the
	// operation needs (revocation, end session).
	ErrNotSupported = errors.New("oidcauth: not supported by the provider")
	// ErrVerifyOnly means a browser login was started or finished on a client
	// configured with Config.VerifyOnly.
	ErrVerifyOnly = errors.New("oidcauth: client only verifies ID tokens")
)

// ProviderError is an error returned by the provider at the callback
// (`error`/`error_description` parameters), e.g. access_denied when the user
// has no grant for the project, or login_required after prompt=none.
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
// missing code, rejected code, token or refresh token, failed auth_time/acr
// check) rather than the provider being unreachable. Handlers typically map
// it to 401 versus 502.
func IsUserError(err error) bool {
	var pe *ProviderError
	var te *tokenError
	return errors.Is(err, ErrInvalidState) || errors.Is(err, ErrMissingCode) ||
		errors.As(err, &pe) || errors.As(err, &te)
}

// tokenError wraps a token response the provider or this library rejected:
// invalid_grant, an invalid ID token, a failed auth_time or acr check.
type tokenError struct {
	op  string
	err error
}

func (e *tokenError) Error() string { return "oidcauth: " + e.op + " failed: " + e.err.Error() }
func (e *tokenError) Unwrap() error { return e.err }

// classify separates network failures (provider unreachable) from rejected
// requests.
func classify(op string, err error) error {
	var netErr *url.Error
	if errors.As(err, &netErr) {
		return fmt.Errorf("oidcauth: %s: provider unreachable: %w", op, err)
	}
	return &tokenError{op: op, err: err}
}

// Client is safe for concurrent use. Provider discovery happens lazily on the
// first use (and is retried until it succeeds), so an unreachable provider
// never prevents the application from starting; local login keeps working.
type Client struct {
	cfg   Config
	flows *flowCodec

	mu        sync.Mutex
	rp        rp.RelyingParty
	refreshRP rp.RelyingParty
	discovery *oidc.DiscoveryConfiguration
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

// Discovery returns the provider metadata (OpenID Connect Discovery 1.0),
// e.g. to check scopes_supported or backchannel_logout_supported.
func (c *Client) Discovery(ctx context.Context) (*oidc.DiscoveryConfiguration, error) {
	if _, err := c.relyingParty(ctx); err != nil {
		return nil, err
	}
	return c.discovery, nil
}

// authMethod resolves AuthMethodAuto from the configured credentials.
func (c *Client) authMethod() string {
	if c.cfg.TokenEndpointAuthMethod != AuthMethodAuto {
		return c.cfg.TokenEndpointAuthMethod
	}
	switch {
	case len(c.cfg.ClientKey) > 0:
		return AuthMethodPrivateKeyJWT
	case c.cfg.ClientSecret == "":
		return AuthMethodNone
	}
	return AuthMethodAuto
}

func (c *Client) relyingParty(ctx context.Context) (rp.RelyingParty, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rp != nil {
		return c.rp, nil
	}
	discovery, err := client.Discover(ctx, c.cfg.Issuer, c.cfg.HTTPClient, c.cfg.DiscoveryURL)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: provider discovery failed: %w", err)
	}
	party, err := c.newParty(ctx, c.cfg.Scopes, func(ctx context.Context) string {
		nonce, _ := ctx.Value(nonceKey{}).(string)
		return nonce
	})
	if err != nil {
		return nil, err
	}
	c.rp, c.discovery = party, discovery
	return party, nil
}

// refreshParty is a second relying party for the refresh_token grant. It
// sends no `scope`, so the refreshed grant keeps the originally granted scopes
// (RFC 6749, section 6), and it does not check `nonce`: a refreshed ID token
// carries the nonce of the original login, which the app does not keep.
func (c *Client) refreshParty(ctx context.Context) (rp.RelyingParty, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshRP != nil {
		return c.refreshRP, nil
	}
	party, err := c.newParty(ctx, nil, nil)
	if err != nil {
		return nil, err
	}
	c.refreshRP = party
	return party, nil
}

func (c *Client) newParty(ctx context.Context, scopes []string, nonce func(context.Context) string) (rp.RelyingParty, error) {
	opts := []rp.Option{
		rp.WithHTTPClient(c.cfg.HTTPClient),
		rp.WithVerifierOpts(rp.WithNonce(nonce)),
		rp.WithSigningAlgsFromDiscovery(),
	}
	if c.cfg.DiscoveryURL != "" {
		opts = append(opts, rp.WithCustomDiscoveryUrl(c.cfg.DiscoveryURL))
	}
	switch c.authMethod() {
	case AuthMethodClientSecretBasic:
		opts = append(opts, rp.WithAuthStyle(oauth2.AuthStyleInHeader))
	case AuthMethodClientSecretPost, AuthMethodNone:
		opts = append(opts, rp.WithAuthStyle(oauth2.AuthStyleInParams))
	case AuthMethodPrivateKeyJWT:
		opts = append(opts,
			rp.WithAuthStyle(oauth2.AuthStyleInParams),
			rp.WithJWTProfile(rp.SignerFromKeyAndKeyID(c.cfg.ClientKey, c.cfg.ClientKeyID)),
		)
	}
	party, err := rp.NewRelyingPartyOIDC(ctx,
		c.cfg.Issuer, c.cfg.ClientID, c.cfg.ClientSecret, c.cfg.RedirectURL, scopes, opts...)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: provider discovery failed: %w", err)
	}
	return party, nil
}

// clientAssertion returns the token endpoint options for private_key_jwt
// (RFC 7523); none for the other methods.
func (c *Client) clientAssertion(party rp.RelyingParty) ([]rp.CodeExchangeOpt, error) {
	if party.Signer() == nil {
		return nil, nil
	}
	assertion, err := client.SignedJWTProfileAssertion(c.cfg.ClientID, []string{c.cfg.Issuer}, time.Minute, party.Signer())
	if err != nil {
		return nil, fmt.Errorf("oidcauth: sign client assertion: %w", err)
	}
	return []rp.CodeExchangeOpt{rp.WithClientAssertionJWT(assertion)}, nil
}
