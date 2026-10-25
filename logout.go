package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// LogoutOption customises the RP-initiated logout request.
type LogoutOption func(url.Values)

// WithLogoutHint sets `logout_hint` (e.g. the login name) so the provider
// knows which session to end when no id_token_hint is available.
func WithLogoutHint(hint string) LogoutOption {
	return func(q url.Values) { q.Set("logout_hint", hint) }
}

// WithLogoutUILocales sets `ui_locales` for the provider logout page.
func WithLogoutUILocales(l ...string) LogoutOption {
	return func(q url.Values) { q.Set("ui_locales", strings.Join(l, " ")) }
}

// LogoutURL builds the RP-initiated logout URL (OpenID Connect RP-Initiated
// Logout 1.0) at the end_session_endpoint. It returns ErrNotSupported when
// the provider does not advertise one. postLogoutRedirect must be registered
// at the provider; empty uses Config.PostLogoutRedirectURL. Pass the ID token
// of the login (Identity.Tokens.IDToken) as idTokenHint whenever available.
func (c *Client) LogoutURL(ctx context.Context, idTokenHint, postLogoutRedirect, state string, opts ...LogoutOption) (string, error) {
	party, err := c.relyingParty(ctx)
	if err != nil {
		return "", err
	}
	endpoint := party.GetEndSessionEndpoint()
	if endpoint == "" {
		return "", ErrNotSupported
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
	for _, opt := range opts {
		opt(q)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// BackChannelLogoutEvent is the event member of a logout token.
const BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// ErrInvalidLogoutToken means a back-channel logout token failed validation.
var ErrInvalidLogoutToken = errors.New("oidcauth: invalid logout token")

// LogoutToken is a verified back-channel logout request (OpenID Connect
// Back-Channel Logout 1.0). The app ends the sessions it holds for Subject
// (all of them) or for SessionID (that provider session only), whichever is
// set; both may be.
type LogoutToken struct {
	Issuer    string
	Subject   string
	SessionID string
	// JWTID identifies the token. Reject a JWTID seen before the token's
	// Expiry to stop replays.
	JWTID    string
	IssuedAt time.Time
	Expiry   time.Time
	Claims   map[string]any
}

// logoutTokenSkew tolerates clock differences on iat/exp.
const logoutTokenSkew = time.Minute

// logoutClaims adds the signature algorithm hook oidc.CheckSignature needs.
type logoutClaims struct {
	oidc.LogoutTokenClaims
}

func (*logoutClaims) SetSignatureAlgorithm(jose.SignatureAlgorithm) {}

// VerifyLogoutToken validates the `logout_token` POSTed to the back-channel
// logout URI (section 2.6): signature against the provider JWKS, iss, aud,
// iat, exp, the backchannel-logout event, sub and/or sid, and the absence of
// nonce (which tells it apart from an ID token).
func (c *Client) VerifyLogoutToken(ctx context.Context, raw string) (*LogoutToken, error) {
	party, err := c.relyingParty(ctx)
	if err != nil {
		return nil, err
	}
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidLogoutToken, fmt.Sprintf(format, args...))
	}

	var claims logoutClaims
	payload, err := oidc.ParseToken(raw, &claims)
	if err != nil {
		return nil, invalid("%v", err)
	}
	if typ, err := tokenType(raw); err != nil {
		return nil, invalid("%v", err)
	} else if typ != "" && !strings.EqualFold(typ, "logout+jwt") && !strings.EqualFold(typ, "JWT") {
		return nil, invalid("typ %q", typ)
	}
	verifier := party.IDTokenVerifier()
	if err := oidc.CheckSignature(ctx, raw, payload, &claims, verifier.SupportedSignAlgs, verifier.KeySet); err != nil {
		return nil, invalid("%v", err)
	}
	t := claims.LogoutTokenClaims
	if t.Issuer != c.cfg.Issuer {
		return nil, invalid("iss %q", t.Issuer)
	}
	if !slices.Contains([]string(t.Audience), c.cfg.ClientID) {
		return nil, invalid("aud does not contain client id")
	}
	now := time.Now()
	issuedAt, expiry := t.IssuedAt.AsTime(), t.Expiration.AsTime()
	if t.IssuedAt == 0 || issuedAt.After(now.Add(logoutTokenSkew)) {
		return nil, invalid("iat missing or in the future")
	}
	if t.Expiration == 0 || !now.Add(-logoutTokenSkew).Before(expiry) {
		return nil, invalid("exp missing or passed")
	}
	if t.JWTID == "" {
		return nil, invalid("jti missing")
	}
	if t.Subject == "" && t.SessionID == "" {
		return nil, invalid("sub and sid both missing")
	}
	if event, ok := t.Events[BackChannelLogoutEvent]; !ok {
		return nil, invalid("backchannel-logout event missing")
	} else if _, isObject := event.(map[string]any); !isObject {
		return nil, invalid("backchannel-logout event must be a JSON object")
	}
	if _, ok := t.Claims["nonce"]; ok {
		return nil, invalid("nonce must not be present")
	}
	all, err := jwtPayload(raw)
	if err != nil {
		return nil, invalid("%v", err)
	}
	return &LogoutToken{
		Issuer:    t.Issuer,
		Subject:   t.Subject,
		SessionID: t.SessionID,
		JWTID:     t.JWTID,
		IssuedAt:  issuedAt,
		Expiry:    expiry,
		Claims:    all,
	}, nil
}

// tokenType reads the JOSE `typ` header without verifying the token.
func tokenType(raw string) (string, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
		jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
	})
	if err != nil {
		return "", err
	}
	if len(jws.Signatures) != 1 {
		return "", errors.New("expected exactly one signature")
	}
	typ, _ := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	return typ, nil
}
