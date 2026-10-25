// Package oidctest runs an in-process OpenID Provider for tests: discovery,
// JWKS, authorization (driven by Authorize), token (authorization_code with
// PKCE S256 and refresh_token), userinfo, revocation and end-session
// endpoints, with RS256-signed ID tokens and back-channel logout tokens. It
// lets applications test their OIDC login end to end without a real Zitadel.
//
//	op := oidctest.NewProvider(t, "client-id", "client-secret")
//	client, _ := oidcauth.New(oidcauth.Config{Issuer: op.Issuer(), ClientID: "client-id", ...})
//	authURL, cookie, _ := client.Start(ctx)
//	query := op.Authorize(t, authURL, oidctest.User{Subject: "u1", Email: "a@b.c", EmailVerified: true})
//	res, err := client.Finish(ctx, query, cookie.Value)
//
// Claims follow the granted scopes like a real provider: email claims need
// the email scope, profile claims the profile scope, and so on.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// User is the identity the fake provider asserts.
type User struct {
	Subject       string
	Email         string // email scope
	EmailVerified bool   // email scope
	Name          string // profile scope
	PhoneNumber   string // phone scope
	PhoneVerified bool   // phone scope
	// Address is the address claim (address scope), e.g.
	// {"locality": "Ha Noi", "country": "VN"}.
	Address map[string]any

	// AuthTime is the auth_time claim. Defaults to the time of Authorize.
	AuthTime time.Time
	// ACR is the acr claim. Defaults to the first requested acr_values.
	ACR string
	// AMR is the amr claim.
	AMR []string

	// Roles are emitted as Zitadel project roles
	// (`urn:zitadel:iam:org:project:roles`), whatever the scopes.
	Roles []string
	// Extra claims added to both the ID token and userinfo. Standard claims
	// among them (given_name, phone_number, ...) still follow the scopes.
	Extra map[string]any
	// UserInfoOnly claims appear only in userinfo (not the ID token), like
	// Zitadel profile claims without "User Info inside ID Token". They also
	// follow the scopes.
	UserInfoOnly map[string]any
}

// scopeClaims lists the standard claims each scope releases
// (OpenID Connect Core 1.0, section 5.4).
var scopeClaims = map[string][]string{
	"profile": {"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username",
		"profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"},
	"email":   {"email", "email_verified"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
}

// claimScope maps a standard claim to the scope that releases it.
var claimScope = func() map[string]string {
	m := map[string]string{}
	for scope, claims := range scopeClaims {
		for _, c := range claims {
			m[c] = scope
		}
	}
	return m
}()

// Provider is a fake OpenID Provider.
type Provider struct {
	Server   *httptest.Server
	ClientID string
	// ClientSecret authenticates the client with client_secret_basic or
	// client_secret_post. Empty means a public client (auth method none),
	// unless ClientPublicKey is set.
	ClientSecret string
	// ClientPublicKey enables private_key_jwt: the client_assertion must be
	// signed by the matching private key.
	ClientPublicKey crypto.PublicKey

	// MutateIDToken alters the next issued ID tokens, for negative tests.
	MutateIDToken func(claims map[string]any)
	// GrantScopes decides the granted scopes from the requested ones.
	// Defaults to granting everything requested.
	GrantScopes func(requested []string) []string
	// OmitScopeInResponse leaves `scope` out of token responses.
	OmitScopeInResponse bool
	// RefreshWithoutIDToken makes refresh_token responses omit the ID token.
	RefreshWithoutIDToken bool

	key   *rsa.PrivateKey
	keyID string

	mu         sync.Mutex
	codes      map[string]grant
	access     map[string]map[string]any
	refresh    map[string]grant
	revoked    []string
	lastAuth   string
	lastAuthRq url.Values
}

// grant is what an authorization code or refresh token stands for.
type grant struct {
	user      User
	scopes    []string
	nonce     string
	challenge string
	redirect  string
	sid       string
	authTime  time.Time
	acr       string
}

// NewProvider starts a provider; it is closed with t.Cleanup.
func NewProvider(t testing.TB, clientID, clientSecret string) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidctest: generate key: %v", err)
	}
	p := &Provider{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		key:          key,
		keyID:        "test-key",
		codes:        map[string]grant{},
		access:       map[string]map[string]any{},
		refresh:      map[string]grant{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/keys", p.jwks)
	mux.HandleFunc("/oauth/v2/token", p.token)
	mux.HandleFunc("/oauth/v2/revoke", p.revoke)
	mux.HandleFunc("/oidc/v1/userinfo", p.userinfo)
	mux.HandleFunc("/oidc/v1/end_session", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Server.Close)
	return p
}

// Issuer returns the issuer URL.
func (p *Provider) Issuer() string { return p.Server.URL }

// LastAuthRequest returns the parameters of the last authorization request
// passed to Authorize.
func (p *Provider) LastAuthRequest() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastAuthRq
}

// LastClientAuth returns the client authentication method of the last token
// or revocation request: client_secret_basic, client_secret_post,
// private_key_jwt or none.
func (p *Provider) LastClientAuth() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastAuth
}

// Revoked returns the tokens revoked so far.
func (p *Provider) Revoked() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.revoked...)
}

// Authorize plays the browser + provider login page: it reads the
// authorization request produced by the relying party, records state, nonce,
// scopes and PKCE challenge, and returns the callback parameters (code,
// state and the RFC 9207 iss).
func (p *Provider) Authorize(t testing.TB, authURL string, user User) url.Values {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("oidctest: parse auth url: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != p.ClientID {
		t.Fatalf("oidctest: client_id = %q, want %q", q.Get("client_id"), p.ClientID)
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("oidctest: response_type = %q, want code", q.Get("response_type"))
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("oidctest: PKCE S256 challenge missing")
	}
	requested := strings.Fields(q.Get("scope"))
	if !slices.Contains(requested, "openid") {
		t.Fatalf("oidctest: scope %q lacks openid", q.Get("scope"))
	}
	scopes := requested
	if p.GrantScopes != nil {
		scopes = p.GrantScopes(requested)
	}
	authTime := user.AuthTime
	if authTime.IsZero() {
		authTime = time.Now()
	}
	acr := user.ACR
	if values := strings.Fields(q.Get("acr_values")); acr == "" && len(values) > 0 {
		acr = values[0]
	}

	code := randomString()
	p.mu.Lock()
	p.lastAuthRq = q
	p.codes[code] = grant{
		user:      user,
		scopes:    scopes,
		nonce:     q.Get("nonce"),
		challenge: q.Get("code_challenge"),
		redirect:  q.Get("redirect_uri"),
		sid:       "sid-" + randomString()[:12],
		authTime:  authTime,
		acr:       acr,
	}
	p.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {p.Server.URL}}
}

// LogoutToken signs a back-channel logout token for the client
// (OpenID Connect Back-Channel Logout 1.0). Pass sub and/or sid. mutate, when
// non-nil, alters the claims before signing, for negative tests.
func (p *Provider) LogoutToken(sub, sid string, mutate func(map[string]any)) string {
	now := time.Now()
	claims := map[string]any{
		"iss":    p.Server.URL,
		"aud":    []string{p.ClientID},
		"iat":    now.Unix(),
		"exp":    now.Add(2 * time.Minute).Unix(),
		"jti":    randomString(),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	if sub != "" {
		claims["sub"] = sub
	}
	if sid != "" {
		claims["sid"] = sid
	}
	if mutate != nil {
		mutate(claims)
	}
	return p.signTyped(claims, "logout+jwt")
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	base := p.Server.URL
	writeJSON(w, map[string]any{
		"issuer":                                         base,
		"authorization_endpoint":                         base + "/oauth/v2/authorize",
		"token_endpoint":                                 base + "/oauth/v2/token",
		"userinfo_endpoint":                              base + "/oidc/v1/userinfo",
		"revocation_endpoint":                            base + "/oauth/v2/revoke",
		"end_session_endpoint":                           base + "/oidc/v1/end_session",
		"jwks_uri":                                       base + "/keys",
		"scopes_supported":                               []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query", "form_post"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		"claims_parameter_supported":                     true,
		"backchannel_logout_supported":                   true,
		"backchannel_logout_session_supported":           true,
		"authorization_response_iss_parameter_supported": true,
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &p.key.PublicKey, KeyID: p.keyID, Algorithm: string(jose.RS256), Use: "sig",
	}}})
}

// authenticateClient checks the client credentials of a token or revocation
// request and records the method used.
func (p *Provider) authenticateClient(r *http.Request) bool {
	method, ok := p.clientAuth(r)
	p.mu.Lock()
	p.lastAuth = method
	p.mu.Unlock()
	return ok
}

func (p *Provider) clientAuth(r *http.Request) (string, bool) {
	if id, secret, ok := r.BasicAuth(); ok {
		return "client_secret_basic", p.ClientSecret != "" && id == p.ClientID && secret == p.ClientSecret
	}
	form := r.PostForm
	if assertion := form.Get("client_assertion"); assertion != "" {
		if p.ClientPublicKey == nil ||
			form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return "private_key_jwt", false
		}
		return "private_key_jwt", p.verifyClientAssertion(assertion)
	}
	if secret := form.Get("client_secret"); secret != "" {
		return "client_secret_post", p.ClientSecret != "" && form.Get("client_id") == p.ClientID && secret == p.ClientSecret
	}
	return "none", p.ClientSecret == "" && p.ClientPublicKey == nil && form.Get("client_id") == p.ClientID
}

func (p *Provider) verifyClientAssertion(raw string) bool {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256})
	if err != nil {
		return false
	}
	payload, err := jws.Verify(p.ClientPublicKey)
	if err != nil {
		return false
	}
	var c struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Exp int64           `json:"exp"`
	}
	if json.Unmarshal(payload, &c) != nil || c.Iss != p.ClientID || c.Sub != p.ClientID || c.Exp < time.Now().Unix() {
		return false
	}
	var auds []string
	if json.Unmarshal(c.Aud, &auds) != nil {
		var one string
		if json.Unmarshal(c.Aud, &one) != nil {
			return false
		}
		auds = []string{one}
	}
	return slices.Contains(auds, p.Server.URL) || slices.Contains(auds, p.Server.URL+"/oauth/v2/token")
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !p.authenticateClient(r) {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.codeGrant(w, r)
	case "refresh_token":
		p.refreshGrant(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (p *Provider) codeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	p.mu.Lock()
	g, found := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	if !found || g.redirect != r.PostForm.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	p.issue(w, g, true)
}

func (p *Provider) refreshGrant(w http.ResponseWriter, r *http.Request) {
	old := r.PostForm.Get("refresh_token")
	p.mu.Lock()
	g, found := p.refresh[old]
	delete(p.refresh, old) // rotation: a refresh token is single use
	p.mu.Unlock()
	if !found {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if requested := strings.Fields(r.PostForm.Get("scope")); len(requested) > 0 {
		// RFC 6749, section 6: a refresh may narrow but never widen the grant.
		for _, s := range requested {
			if !slices.Contains(g.scopes, s) {
				oauthError(w, http.StatusBadRequest, "invalid_scope")
				return
			}
		}
		g.scopes = requested
	}
	p.issue(w, g, !p.RefreshWithoutIDToken)
}

// issue writes a token response for g.
func (p *Provider) issue(w http.ResponseWriter, g grant, withIDToken bool) {
	now := time.Now()
	public := p.publicClaims(g.user, g.scopes, false)
	resp := map[string]any{
		"token_type": "Bearer",
		"expires_in": 3600,
	}
	if !p.OmitScopeInResponse {
		resp["scope"] = strings.Join(g.scopes, " ")
	}
	if withIDToken {
		claims := map[string]any{
			"iss":       p.Server.URL,
			"sub":       g.user.Subject,
			"aud":       []string{p.ClientID},
			"azp":       p.ClientID,
			"iat":       now.Unix(),
			"exp":       now.Add(time.Hour).Unix(),
			"auth_time": g.authTime.Unix(),
			"sid":       g.sid,
		}
		if g.nonce != "" {
			claims["nonce"] = g.nonce
		}
		if g.acr != "" {
			claims["acr"] = g.acr
		}
		if len(g.user.AMR) > 0 {
			claims["amr"] = g.user.AMR
		}
		for k, v := range public {
			claims[k] = v
		}
		if p.MutateIDToken != nil {
			p.MutateIDToken(claims)
		}
		resp["id_token"] = p.signTyped(claims, "JWT")
	}

	accessToken := randomString()
	info := map[string]any{"sub": g.user.Subject}
	for k, v := range p.publicClaims(g.user, g.scopes, true) {
		info[k] = v
	}
	resp["access_token"] = accessToken
	p.mu.Lock()
	p.access[accessToken] = info
	if slices.Contains(g.scopes, "offline_access") {
		refreshToken := randomString()
		p.refresh[refreshToken] = g
		resp["refresh_token"] = refreshToken
	}
	p.mu.Unlock()
	writeJSON(w, resp)
}

func (p *Provider) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !p.authenticateClient(r) {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	token := r.PostForm.Get("token")
	p.mu.Lock()
	delete(p.refresh, token)
	delete(p.access, token)
	p.revoked = append(p.revoked, token)
	p.mu.Unlock()
	// RFC 7009, section 2.2: 200 even for unknown tokens.
	w.WriteHeader(http.StatusOK)
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p.mu.Lock()
	info, ok := p.access[auth[len(prefix):]]
	p.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, info)
}

// publicClaims returns the user claims released by scopes; userinfo adds
// UserInfoOnly.
func (p *Provider) publicClaims(u User, scopes []string, userinfo bool) map[string]any {
	all := map[string]any{}
	if u.Email != "" {
		all["email"] = u.Email
		all["email_verified"] = u.EmailVerified
	}
	if u.Name != "" {
		all["name"] = u.Name
	}
	if u.PhoneNumber != "" {
		all["phone_number"] = u.PhoneNumber
		all["phone_number_verified"] = u.PhoneVerified
	}
	if len(u.Address) > 0 {
		all["address"] = u.Address
	}
	for k, v := range u.Extra {
		all[k] = v
	}
	if userinfo {
		for k, v := range u.UserInfoOnly {
			all[k] = v
		}
	}
	out := map[string]any{}
	for k, v := range all {
		if scope, standard := claimScope[k]; standard && !slices.Contains(scopes, scope) {
			continue
		}
		out[k] = v
	}
	if len(u.Roles) > 0 {
		roles := map[string]any{}
		for _, r := range u.Roles {
			roles[r] = map[string]any{"org-id": "example.org"}
		}
		out["urn:zitadel:iam:org:project:roles"] = roles
	}
	return out
}

func (p *Provider) signTyped(claims map[string]any, typ string) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: p.keyID}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)),
	)
	if err != nil {
		panic(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return out
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
