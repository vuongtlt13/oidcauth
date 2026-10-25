package oidcauth

import (
	"encoding/json"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Identity is what the provider asserted about the signed-in user. The library
// never creates or links local accounts: the application decides what to do
// with an Identity (link by Subject, match by verified Email, auto-provision,
// reject, ...).
//
// Fields map the standard claims of OpenID Connect Core 1.0, section 5.1;
// which ones are filled depends on the granted scopes (ScopeProfile,
// ScopeEmail, ScopePhone, ScopeAddress) and on the provider.
type Identity struct {
	// Issuer and Subject together are the stable, unique key of the user at
	// the provider. Store both; never key local accounts on email alone.
	Issuer  string
	Subject string

	// email scope.
	Email         string
	EmailVerified bool

	// profile scope.
	Name              string
	GivenName         string
	FamilyName        string
	MiddleName        string
	Nickname          string
	PreferredUsername string
	Profile           string
	Picture           string
	Website           string
	Gender            string
	// Birthdate is YYYY-MM-DD, or YYYY / 0000-MM-DD when partially disclosed.
	Birthdate string
	Zoneinfo  string
	Locale    string
	UpdatedAt time.Time

	// phone scope.
	PhoneNumber         string
	PhoneNumberVerified bool

	// address scope. Nil when the provider sent no address.
	Address *Address

	// Authentication context from the ID token.
	AuthTime time.Time // when the user last authenticated (auth_time)
	ACR      string    // authentication context class reference (acr)
	AMR      []string  // authentication methods, e.g. "pwd", "otp", "mfa" (amr)
	// SessionID is the provider session (sid). Store it with the app session
	// to honour back-channel logout by session.
	SessionID string

	// Roles extracted by Config.RoleExtractor.
	Roles []string
	// Claims holds every claim from the ID token merged with userinfo, for
	// provider-specific fields. Protected ID token claims (iss, sub, aud,
	// exp, nonce, auth_time, sid, ...) are never overridden by userinfo.
	Claims map[string]any

	// Tokens returned by the provider. IDToken is needed as id_token_hint for
	// RP-initiated logout; access/refresh tokens are only useful if the app
	// calls provider APIs on behalf of the user or refreshes the login.
	Tokens Tokens
}

// Address is the `address` claim (section 5.1.1).
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// Tokens are the raw tokens from the token endpoint.
type Tokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	TokenType    string
	Expiry       time.Time
	// Scopes actually granted: the token response `scope` when present,
	// else the scopes requested (RFC 6749, section 5.1). Providers may grant
	// fewer scopes than requested.
	Scopes []string
}

// HasScope reports whether scope was granted.
func (t Tokens) HasScope(scope string) bool { return slices.Contains(t.Scopes, scope) }

// tokensFrom copies an oauth2 token; requestedScope is the fallback for the
// granted scope.
func tokensFrom(t *oauth2.Token, idToken, requestedScope string) Tokens {
	scope, _ := t.Extra("scope").(string)
	if scope == "" {
		scope = requestedScope
	}
	return Tokens{
		IDToken:      idToken,
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.Type(),
		Expiry:       t.Expiry,
		Scopes:       strings.Fields(scope),
	}
}

// HasRole reports whether the identity carries role.
func (i *Identity) HasRole(role string) bool { return slices.Contains(i.Roles, role) }

// DisplayName returns the best human-readable name available.
func (i *Identity) DisplayName() string {
	for _, v := range []string{i.Name, strings.TrimSpace(i.GivenName + " " + i.FamilyName), i.PreferredUsername, i.Nickname, i.Email} {
		if v != "" {
			return v
		}
	}
	return i.Subject
}

func identityFromClaims(claims map[string]any, roleExtractor func(map[string]any) []string) *Identity {
	return &Identity{
		Issuer:              stringClaim(claims, "iss"),
		Subject:             stringClaim(claims, "sub"),
		Email:               strings.TrimSpace(stringClaim(claims, "email")),
		EmailVerified:       boolClaim(claims, "email_verified"),
		Name:                stringClaim(claims, "name"),
		GivenName:           stringClaim(claims, "given_name"),
		FamilyName:          stringClaim(claims, "family_name"),
		MiddleName:          stringClaim(claims, "middle_name"),
		Nickname:            stringClaim(claims, "nickname"),
		PreferredUsername:   stringClaim(claims, "preferred_username"),
		Profile:             stringClaim(claims, "profile"),
		Picture:             stringClaim(claims, "picture"),
		Website:             stringClaim(claims, "website"),
		Gender:              stringClaim(claims, "gender"),
		Birthdate:           stringClaim(claims, "birthdate"),
		Zoneinfo:            stringClaim(claims, "zoneinfo"),
		Locale:              stringClaim(claims, "locale"),
		UpdatedAt:           timeClaim(claims, "updated_at"),
		PhoneNumber:         strings.TrimSpace(stringClaim(claims, "phone_number")),
		PhoneNumberVerified: boolClaim(claims, "phone_number_verified"),
		Address:             addressClaim(claims),
		AuthTime:            timeClaim(claims, "auth_time"),
		ACR:                 stringClaim(claims, "acr"),
		AMR:                 stringsClaim(claims, "amr"),
		SessionID:           stringClaim(claims, "sid"),
		Roles:               roleExtractor(claims),
		Claims:              claims,
	}
}

const zitadelRolesClaim = "urn:zitadel:iam:org:project:roles"

// DefaultRoleExtractor understands, in order:
//   - Zitadel `urn:zitadel:iam:org:project:roles` and
//     `urn:zitadel:iam:org:project:<id>:roles` (object keyed by role name);
//   - a plain `roles` claim (array of strings, or object keyed by role);
//   - a `groups` claim (array of strings).
//
// The result is de-duplicated and sorted.
func DefaultRoleExtractor(claims map[string]any) []string {
	set := map[string]struct{}{}
	for key, value := range claims {
		if key == zitadelRolesClaim ||
			(strings.HasPrefix(key, "urn:zitadel:iam:org:project:") && strings.HasSuffix(key, ":roles")) {
			addRoleKeys(set, value)
		}
	}
	if len(set) == 0 {
		addRoleKeys(set, claims["roles"])
		addRoleKeys(set, claims["groups"])
	}
	roles := make([]string, 0, len(set))
	for r := range set {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	return roles
}

func addRoleKeys(set map[string]struct{}, value any) {
	switch v := value.(type) {
	case map[string]any:
		for role := range v {
			if role != "" {
				set[role] = struct{}{}
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				set[s] = struct{}{}
			}
		}
	case []string:
		for _, s := range v {
			if s != "" {
				set[s] = struct{}{}
			}
		}
	}
}

func stringClaim(claims map[string]any, key string) string {
	s, _ := claims[key].(string)
	return s
}

// boolClaim accepts JSON booleans and the "true"/"false" strings some
// providers send for email_verified.
func boolClaim(claims map[string]any, key string) bool {
	switch v := claims[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

// timeClaim reads a NumericDate (seconds since the epoch, section 2).
func timeClaim(claims map[string]any, key string) time.Time {
	var secs float64
	switch v := claims[key].(type) {
	case float64:
		secs = v
	case json.Number:
		secs, _ = v.Float64()
	case int64:
		secs = float64(v)
	default:
		return time.Time{}
	}
	if secs <= 0 || math.IsInf(secs, 0) || math.IsNaN(secs) {
		return time.Time{}
	}
	return time.Unix(int64(secs), 0)
}

func stringsClaim(claims map[string]any, key string) []string {
	var out []string
	switch v := claims[key].(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, v...)
	case string:
		if v != "" {
			out = []string{v}
		}
	}
	return out
}

func addressClaim(claims map[string]any) *Address {
	switch v := claims["address"].(type) {
	case map[string]any:
		raw, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		var a Address
		if json.Unmarshal(raw, &a) != nil || a == (Address{}) {
			return nil
		}
		return &a
	case string:
		// Some providers send a plain formatted string.
		if v != "" {
			return &Address{Formatted: v}
		}
	}
	return nil
}
