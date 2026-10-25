package oidcauth

import (
	"sort"
	"strings"
	"time"
)

// Identity is what the provider asserted about the signed-in user. The library
// never creates or links local accounts: the application decides what to do
// with an Identity (link by Subject, match by verified Email, auto-provision,
// reject, ...).
type Identity struct {
	// Issuer and Subject together are the stable, unique key of the user at
	// the provider. Store both; never key local accounts on email alone.
	Issuer  string
	Subject string

	Email             string
	EmailVerified     bool
	Name              string
	GivenName         string
	FamilyName        string
	PreferredUsername string
	Picture           string
	Locale            string

	// Roles extracted by Config.RoleExtractor.
	Roles []string
	// Claims holds every claim from the ID token merged with userinfo
	// (userinfo wins on conflicts), for provider-specific fields.
	Claims map[string]any

	// Tokens returned by the provider. IDToken is needed as id_token_hint for
	// RP-initiated logout; access/refresh tokens are only useful if the app
	// calls provider APIs on behalf of the user.
	Tokens Tokens
}

// Tokens are the raw tokens from the token endpoint.
type Tokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	TokenType    string
	Expiry       time.Time
}

// HasRole reports whether the identity carries role.
func (i *Identity) HasRole(role string) bool {
	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// DisplayName returns the best human-readable name available.
func (i *Identity) DisplayName() string {
	for _, v := range []string{i.Name, strings.TrimSpace(i.GivenName + " " + i.FamilyName), i.PreferredUsername, i.Email} {
		if v != "" {
			return v
		}
	}
	return i.Subject
}

func identityFromClaims(claims map[string]any, roleExtractor func(map[string]any) []string) *Identity {
	return &Identity{
		Issuer:            stringClaim(claims, "iss"),
		Subject:           stringClaim(claims, "sub"),
		Email:             strings.TrimSpace(stringClaim(claims, "email")),
		EmailVerified:     boolClaim(claims, "email_verified"),
		Name:              stringClaim(claims, "name"),
		GivenName:         stringClaim(claims, "given_name"),
		FamilyName:        stringClaim(claims, "family_name"),
		PreferredUsername: stringClaim(claims, "preferred_username"),
		Picture:           stringClaim(claims, "picture"),
		Locale:            stringClaim(claims, "locale"),
		Roles:             roleExtractor(claims),
		Claims:            claims,
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
