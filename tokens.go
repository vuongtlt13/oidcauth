package oidcauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// RefreshResult is the outcome of a refresh_token grant.
type RefreshResult struct {
	// Tokens are the new tokens. RefreshToken keeps the old value when the
	// provider did not rotate it.
	Tokens Tokens
	// Identity is rebuilt from the refreshed ID token (merged with userinfo)
	// when the provider returned one, nil otherwise. Its Subject is checked
	// against the previous one by the caller, who knows it.
	Identity *Identity
}

// Refresh exchanges a refresh token for new tokens (OpenID Connect Core 1.0,
// section 12). A refresh token is only issued when ScopeOfflineAccess was
// granted (or by provider policy). The refreshed grant keeps the originally
// granted scopes. A returned ID token is fully verified (signature, iss, aud,
// azp, exp, iat); it carries no fresh nonce, so nonce is not checked.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	if refreshToken == "" {
		return nil, &tokenError{op: "refresh", err: errors.New("refresh token is empty")}
	}
	party, err := c.refreshParty(ctx)
	if err != nil {
		return nil, err
	}
	tokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, party, refreshToken, "", "")
	if err != nil {
		return nil, classify("refresh", err)
	}
	res := &RefreshResult{Tokens: tokensFrom(tokens.Token, tokens.IDToken, "")}
	if res.Tokens.RefreshToken == "" {
		res.Tokens.RefreshToken = refreshToken
	}
	if tokens.IDToken != "" {
		identity, err := c.identityFromTokens(ctx, party, tokens.IDToken, tokens.IDTokenClaims.GetSubject(), tokens.Token)
		if err != nil {
			return nil, err
		}
		identity.Tokens = res.Tokens
		res.Identity = identity
	}
	return res, nil
}

// Revoke revokes a refresh or access token at the provider (RFC 7009). hint
// is TokenTypeHintRefreshToken, TokenTypeHintAccessToken or "". Revoking a
// refresh token usually also ends the grant's access tokens. It returns
// ErrNotSupported when the provider has no revocation_endpoint.
func (c *Client) Revoke(ctx context.Context, token, hint string) error {
	party, err := c.relyingParty(ctx)
	if err != nil {
		return err
	}
	if revoker, ok := party.(client.RevokeCaller); !ok || revoker.GetRevokeEndpoint() == "" {
		return ErrNotSupported
	}
	if err := rp.RevokeToken(ctx, party, token, hint); err != nil {
		return classify("revoke", err)
	}
	return nil
}

// UserInfo calls the userinfo endpoint with an access token and returns its
// claims. subject must be the ID token `sub`; a response for another subject
// is rejected (section 5.3.4).
func (c *Client) UserInfo(ctx context.Context, accessToken, subject string) (map[string]any, error) {
	party, err := c.relyingParty(ctx)
	if err != nil {
		return nil, err
	}
	if party.UserinfoEndpoint() == "" {
		return nil, ErrNotSupported
	}
	info, err := rp.Userinfo[*oidc.UserInfo](ctx, accessToken, oidc.BearerToken, subject, party)
	if err != nil {
		return nil, classify("userinfo", err)
	}
	claims := map[string]any{}
	if err := mergeUserInfo(claims, info); err != nil {
		return nil, err
	}
	claims["sub"] = info.Subject
	return claims, nil
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
	"nonce": {}, "auth_time": {}, "acr": {}, "amr": {}, "at_hash": {}, "c_hash": {},
	"sid": {}, "jti": {},
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
