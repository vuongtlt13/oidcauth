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

// DefaultScopes is used when Config.Scopes is empty.
var DefaultScopes = []string{"openid", "profile", "email"}

// Config describes one OpenID Connect relying party (your app) registered at
// one OpenID Provider (Zitadel, Keycloak, Google, ...).
type Config struct {
	// Issuer is the provider issuer URL, e.g. https://id.example.com. It must
	// match the `issuer` in the discovery document exactly.
	Issuer string
	// ClientID and ClientSecret of the app registered at the provider. Leave
	// ClientSecret empty for a public client (PKCE only).
	ClientID     string
	ClientSecret string
	// RedirectURL is the absolute callback URL registered at the provider.
	RedirectURL string
	// Scopes requested at the authorization endpoint. Defaults to DefaultScopes.
	Scopes []string

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
	// HTTPClient is used for discovery, JWKS, token and userinfo requests.
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
	if strings.TrimSpace(c.ClientID) == "" {
		errs = append(errs, errors.New("client id is required"))
	}
	if err := validateAbsoluteURL("redirect url", c.RedirectURL); err != nil {
		errs = append(errs, err)
	}
	if len(c.CookieSecret) < minCookieSecret {
		errs = append(errs, fmt.Errorf("cookie secret must be at least %d characters", minCookieSecret))
	}
	if len(c.Scopes) > 0 && !containsString(c.Scopes, "openid") {
		errs = append(errs, errors.New(`scopes must include "openid"`))
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
