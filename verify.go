package oidcauth

import (
	"context"
	"errors"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

// VerifyOption customises VerifyIDToken.
type VerifyOption func(*verifyOptions)

type verifyOptions struct {
	audience    string
	nonce       *string
	maxAge      time.Duration
	accessToken string
}

// WithAudience sets the client the token was issued to, default
// Config.ClientID: the native app's client id (for Sign in with Apple, the
// bundle id), which may belong to another project of the same provider.
func WithAudience(clientID string) VerifyOption {
	return func(o *verifyOptions) { o.audience = clientID }
}

// WithNonce requires the token `nonce` to equal nonce. Without it the nonce
// is not checked.
func WithNonce(nonce string) VerifyOption { return func(o *verifyOptions) { o.nonce = &nonce } }

// WithTokenMaxAge refuses a token issued more than d ago (now - iat), which
// limits the replay of a leaked token to that window.
func WithTokenMaxAge(d time.Duration) VerifyOption {
	return func(o *verifyOptions) { o.maxAge = d }
}

// WithAccessToken checks the token `at_hash` against accessToken and, unless
// SkipUserInfo is set, merges userinfo claims fetched with it.
func WithAccessToken(accessToken string) VerifyOption {
	return func(o *verifyOptions) { o.accessToken = accessToken }
}

// VerifyIDToken verifies an ID token obtained elsewhere, typically by a
// native app that logged in itself (Sign in with Apple, authorization code +
// PKCE) and sends its ID token to this backend, and returns its identity.
//
// It checks the signature (JWKS), iss, aud, azp, exp and iat like Finish,
// plus the nonce, max age and at_hash when the matching options are given.
// An ID token is a bearer proof of the login: keep WithTokenMaxAge short and
// pass WithNonce when the app can send its nonce.
//
// Errors for an invalid token satisfy IsUserError.
func (c *Client) VerifyIDToken(ctx context.Context, raw string, opts ...VerifyOption) (*Identity, error) {
	if raw == "" {
		return nil, &tokenError{op: "id token", err: errors.New("id token is empty")}
	}
	var o verifyOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.maxAge < 0 {
		return nil, errors.New("oidcauth: token max age must not be negative")
	}
	party, err := c.relyingParty(ctx)
	if err != nil {
		return nil, err
	}

	// A copy of the login verifier (key set, algorithms, issuer) for this
	// token's audience and options.
	v := *party.IDTokenVerifier()
	if o.audience != "" {
		v.ClientID = o.audience
		v.AZP = oidc.DefaultAZPVerifier(o.audience)
	}
	v.Nonce = nil
	if o.nonce != nil {
		nonce := *o.nonce
		v.Nonce = func(context.Context) string { return nonce }
	}
	v.MaxAgeIAT = o.maxAge
	claims, err := rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, raw, &v)
	if err != nil {
		return nil, classify("id token", err)
	}

	var identity *Identity
	if o.accessToken != "" {
		if err := rp.VerifyAccessToken(o.accessToken, claims.GetAccessTokenHash(), claims.GetSignatureAlgorithm()); err != nil {
			return nil, &tokenError{op: "id token", err: err}
		}
		token := &oauth2.Token{AccessToken: o.accessToken, TokenType: oidc.BearerToken}
		identity, err = c.identityFromTokens(ctx, party, raw, claims.GetSubject(), token)
		if err != nil {
			return nil, err
		}
	} else {
		all, err := jwtPayload(raw)
		if err != nil {
			return nil, err
		}
		identity = identityFromClaims(all, c.cfg.RoleExtractor)
	}
	identity.Tokens = Tokens{IDToken: raw, AccessToken: o.accessToken, TokenType: oidc.BearerToken}
	return identity, nil
}
