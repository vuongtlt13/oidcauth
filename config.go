package oidcauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultCookieName = "oidc_flow"
	defaultCookiePath = "/"
	defaultFlowTTL    = 10 * time.Minute
	minCookieSecret   = 32
)

// Token endpoint client authentication methods (OpenID Connect Core 1.0,
// section 9). Config.TokenEndpointAuthMethod selects one.
const (
	// AuthMethodAuto picks client_secret_basic, falling back to
	// client_secret_post, for a client with a secret; private_key_jwt for a
	// client with ClientKey; none for a public client.
	AuthMethodAuto              = ""
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodPrivateKeyJWT     = "private_key_jwt"
	AuthMethodNone              = "none"
)

// DefaultScopes is used when Config.Scopes is empty.
var DefaultScopes = []string{ScopeOpenID, ScopeProfile, ScopeEmail}

// Config describes one OpenID Connect relying party (your app) registered at
// one OpenID Provider (Zitadel, Keycloak, Google, ...).
type Config struct {
	// Issuer is the provider issuer URL, e.g. https://id.example.com. It must
	// match the `issuer` in the discovery document exactly.
	Issuer string
	// DiscoveryURL overrides <Issuer>/.well-known/openid-configuration.
	DiscoveryURL string
	// ClientID of the app registered at the provider.
	ClientID string
	// ClientSecret for client_secret_basic / client_secret_post. Leave it
	// and ClientKey empty for a public client (PKCE only).
	ClientSecret string
	// ClientKey is a PEM private key (RSA or EC) for private_key_jwt client
	// authentication, with ClientKeyID as its `kid`. For Zitadel, take `key`
	// and `keyId` from the application key JSON. Mutually exclusive with
	// ClientSecret.
	ClientKey   []byte
	ClientKeyID string
	// TokenEndpointAuthMethod forces one client authentication method.
	// Defaults to AuthMethodAuto.
	TokenEndpointAuthMethod string
	// RedirectURL is the absolute callback URL registered at the provider.
	RedirectURL string
	// VerifyOnly makes a client that only verifies ID tokens obtained
	// elsewhere (VerifyIDToken), e.g. Sign in with Apple from a native app.
	// RedirectURL and CookieSecret are then not required, and Start/Finish
	// return ErrVerifyOnly.
	VerifyOnly bool
	// Scopes requested at the authorization endpoint. Defaults to
	// DefaultScopes. Must include ScopeOpenID.
	Scopes []string

	// ACRValues are sent as `acr_values` on every login (requested
	// authentication context classes, e.g. a MFA level). Per-request
	// WithACRValues overrides them.
	ACRValues []string
	// RequireACR rejects a login whose ID token `acr` is not one of the
	// requested acr_values. Without it acr_values is only a hint.
	RequireACR bool
	// MaxAge is sent as `max_age` on every login when positive: the provider
	// must re-authenticate a user whose last authentication is older, and the
	// ID token `auth_time` is then checked. Per-request WithMaxAge overrides it.
	MaxAge time.Duration

	// CookieSecret signs and encrypts the short-lived login flow cookie that
	// carries state, nonce and the PKCE verifier. At least 32 characters.
	CookieSecret string
	// CookieName is the flow cookie prefix. Defaults to "oidc_flow".
	CookieName string
	// CookiePath scopes the flow cookie. It must cover the callback path.
	// Defaults to "/".
	CookiePath string
	// CookieInsecure drops the Secure attribute. Only for plain-HTTP local
	// development on hosts browsers do not treat as secure.
	CookieInsecure bool
	// FlowTTL bounds how long a user may stay at the provider login page.
	// Defaults to 10 minutes.
	FlowTTL time.Duration

	// SkipUserInfo disables the userinfo request after the code exchange. By
	// default userinfo claims are merged over the ID token claims, because
	// providers such as Zitadel only put profile/role claims into the ID token
	// when explicitly configured to.
	SkipUserInfo bool
	// RoleExtractor reads roles from the merged claims. Defaults to
	// DefaultRoleExtractor (Zitadel project roles, then `roles`/`groups`).
	RoleExtractor func(claims map[string]any) []string

	// PostLogoutRedirectURL is the default target after RP-initiated logout.
	PostLogoutRedirectURL string
	// HTTPClient is used for discovery, JWKS, token, userinfo and revocation
	// requests.
	HTTPClient *http.Client
}

func (c Config) withDefaults() Config {
	c.Issuer = strings.TrimSpace(c.Issuer)
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.RedirectURL = strings.TrimSpace(c.RedirectURL)
	if len(c.Scopes) == 0 {
		c.Scopes = append([]string(nil), DefaultScopes...)
	}
	if c.CookieName == "" {
		c.CookieName = defaultCookieName
	}
	if c.CookiePath == "" {
		c.CookiePath = defaultCookiePath
	}
	if c.FlowTTL <= 0 {
		c.FlowTTL = defaultFlowTTL
	}
	if c.RoleExtractor == nil {
		c.RoleExtractor = DefaultRoleExtractor
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return c
}

// Validate reports configuration errors without contacting the provider.
func (c Config) Validate() error {
	var errs []error
	if err := validateAbsoluteURL("issuer", c.Issuer); err != nil {
		errs = append(errs, err)
	}
	if c.DiscoveryURL != "" {
		if err := validateAbsoluteURL("discovery url", c.DiscoveryURL); err != nil {
			errs = append(errs, err)
		}
	}
	if strings.TrimSpace(c.ClientID) == "" {
		errs = append(errs, errors.New("client id is required"))
	}
	if !c.VerifyOnly || c.RedirectURL != "" {
		if err := validateAbsoluteURL("redirect url", c.RedirectURL); err != nil {
			errs = append(errs, err)
		}
	}
	if !c.VerifyOnly && len(c.CookieSecret) < minCookieSecret {
		errs = append(errs, fmt.Errorf("cookie secret must be at least %d characters", minCookieSecret))
	}
	if len(c.Scopes) > 0 && !containsString(c.Scopes, ScopeOpenID) {
		errs = append(errs, errors.New(`scopes must include "openid"`))
	}
	if c.ClientSecret != "" && len(c.ClientKey) > 0 {
		errs = append(errs, errors.New("set either client secret or client key, not both"))
	}
	if len(c.ClientKey) > 0 && c.ClientKeyID == "" {
		errs = append(errs, errors.New("client key id is required with client key"))
	}
	switch c.TokenEndpointAuthMethod {
	case AuthMethodAuto:
	case AuthMethodClientSecretBasic, AuthMethodClientSecretPost:
		if c.ClientSecret == "" {
			errs = append(errs, fmt.Errorf("%s requires a client secret", c.TokenEndpointAuthMethod))
		}
	case AuthMethodPrivateKeyJWT:
		if len(c.ClientKey) == 0 {
			errs = append(errs, errors.New("private_key_jwt requires a client key"))
		}
	case AuthMethodNone:
		if c.ClientSecret != "" || len(c.ClientKey) > 0 {
			errs = append(errs, errors.New("auth method none must not have client credentials"))
		}
	default:
		errs = append(errs, fmt.Errorf("unsupported token endpoint auth method %q", c.TokenEndpointAuthMethod))
	}
	if c.MaxAge < 0 {
		errs = append(errs, errors.New("max age must not be negative"))
	}
	if c.RequireACR && len(c.ACRValues) == 0 {
		errs = append(errs, errors.New("require acr needs acr values"))
	}
	return errors.Join(errs...)
}

func validateAbsoluteURL(name, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%s is required", name)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", name)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("%s must use http or https", name)
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
