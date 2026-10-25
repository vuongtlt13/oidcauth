package oidcauth

// Standard scopes (OpenID Connect Core 1.0, sections 3.1.2.1 and 5.4).
const (
	// ScopeOpenID is required: without it the request is plain OAuth 2.0.
	ScopeOpenID = "openid"
	// ScopeProfile requests name, family_name, given_name, middle_name,
	// nickname, preferred_username, profile, picture, website, gender,
	// birthdate, zoneinfo, locale and updated_at.
	ScopeProfile = "profile"
	// ScopeEmail requests email and email_verified.
	ScopeEmail = "email"
	// ScopeAddress requests address.
	ScopeAddress = "address"
	// ScopePhone requests phone_number and phone_number_verified.
	ScopePhone = "phone"
	// ScopeOfflineAccess requests a refresh token usable while the user is
	// not present (section 11). Most providers also require prompt=consent
	// or a client setting to issue one.
	ScopeOfflineAccess = "offline_access"
)

// Values of the `prompt` authorization parameter (section 3.1.2.1, and
// Initiating User Registration 1.0 for "create").
const (
	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"
	PromptCreate        = "create"
)

// Values of the `display` authorization parameter (section 3.1.2.1).
const (
	DisplayPage  = "page"
	DisplayPopup = "popup"
	DisplayTouch = "touch"
	DisplayWAP   = "wap"
)

// Token type hints for Client.Revoke (RFC 7009, section 2.1).
const (
	TokenTypeHintAccessToken  = "access_token"
	TokenTypeHintRefreshToken = "refresh_token"
)

// ClaimsRequest is the `claims` authorization parameter (section 5.5): it
// asks for individual claims in the ID token and/or the userinfo response,
// beyond what the scopes grant. A nil *ClaimRequest value means "requested
// as a voluntary claim" and is encoded as JSON null.
//
//	oidcauth.WithClaims(&oidcauth.ClaimsRequest{
//		IDToken: map[string]*oidcauth.ClaimRequest{
//			"email": {Essential: true},
//			"auth_time": nil,
//		},
//	})
type ClaimsRequest struct {
	UserInfo map[string]*ClaimRequest `json:"userinfo,omitempty"`
	IDToken  map[string]*ClaimRequest `json:"id_token,omitempty"`
}

// ClaimRequest qualifies one requested claim (section 5.5.1).
type ClaimRequest struct {
	Essential bool     `json:"essential,omitempty"`
	Value     string   `json:"value,omitempty"`
	Values    []string `json:"values,omitempty"`
}
