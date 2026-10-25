// Package oidctest runs an in-process OpenID Provider for tests: discovery,
// JWKS, token (authorization_code + PKCE S256) and userinfo endpoints, with
// RS256-signed ID tokens. It lets applications test their OIDC login end to
// end without a real Zitadel.
//
//	op := oidctest.NewProvider(t, "client-id", "client-secret")
//	client, _ := oidcauth.New(oidcauth.Config{Issuer: op.Issuer(), ClientID: "client-id", ...})
//	authURL, cookie, _ := client.Start(ctx)
//	query := op.Authorize(t, authURL, oidctest.User{Subject: "u1", Email: "a@b.c", EmailVerified: true})
//	res, err := client.Finish(ctx, query, cookie.Value)
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// User is the identity the fake provider asserts.
type User struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	// Roles are emitted as Zitadel project roles
	// (`urn:zitadel:iam:org:project:roles`).
	Roles []string
	// Extra claims added to both the ID token and userinfo.
	Extra map[string]any
	// UserInfoOnly claims appear only in userinfo (not the ID token), like
	// Zitadel profile claims without "User Info inside ID Token".
	UserInfoOnly map[string]any
}

// Provider is a fake OpenID Provider.
type Provider struct {
	Server       *httptest.Server
	ClientID     string
	ClientSecret string

	// Mutators for negative tests, applied to the next issued ID tokens.
	MutateIDToken func(claims map[string]any)

	key   *rsa.PrivateKey
	keyID string

	mu     sync.Mutex
	codes  map[string]pendingCode
	access map[string]map[string]any
}

type pendingCode struct {
	user      User
	nonce     string
	challenge string
	redirect  string
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
		codes:        map[string]pendingCode{},
		access:       map[string]map[string]any{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/keys", p.jwks)
	mux.HandleFunc("/oauth/v2/token", p.token)
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

// Authorize plays the browser + provider login page: it reads the
// authorization request produced by the relying party, records state, nonce
// and PKCE challenge, and returns the callback query (code + state).
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
	code := randomString()
	p.mu.Lock()
	p.codes[code] = pendingCode{
		user:      user,
		nonce:     q.Get("nonce"),
		challenge: q.Get("code_challenge"),
		redirect:  q.Get("redirect_uri"),
	}
	p.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")}}
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	base := p.Server.URL
	writeJSON(w, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/v2/authorize",
		"token_endpoint":                        base + "/oauth/v2/token",
		"userinfo_endpoint":                     base + "/oidc/v1/userinfo",
		"end_session_endpoint":                  base + "/oidc/v1/end_session",
		"jwks_uri":                              base + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &p.key.PublicKey, KeyID: p.keyID, Algorithm: string(jose.RS256), Use: "sig",
	}}})
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || secret != p.ClientSecret {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	pending, found := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	if !found || pending.redirect != r.PostForm.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != pending.challenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	now := time.Now()
	claims := map[string]any{
		"iss":   p.Server.URL,
		"sub":   pending.user.Subject,
		"aud":   []string{p.ClientID},
		"azp":   p.ClientID,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": pending.nonce,
	}
	public := p.publicClaims(pending.user)
	for k, v := range public {
		claims[k] = v
	}
	if p.MutateIDToken != nil {
		p.MutateIDToken(claims)
	}
	idToken := p.sign(claims)

	accessToken := randomString()
	info := map[string]any{"sub": pending.user.Subject}
	for k, v := range public {
		info[k] = v
	}
	for k, v := range pending.user.UserInfoOnly {
		info[k] = v
	}
	p.mu.Lock()
	p.access[accessToken] = info
	p.mu.Unlock()

	writeJSON(w, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) <= len(prefix) {
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

func (p *Provider) publicClaims(u User) map[string]any {
	out := map[string]any{}
	if u.Email != "" {
		out["email"] = u.Email
		out["email_verified"] = u.EmailVerified
	}
	if u.Name != "" {
		out["name"] = u.Name
	}
	if len(u.Roles) > 0 {
		roles := map[string]any{}
		for _, r := range u.Roles {
			roles[r] = map[string]any{"org-id": "example.org"}
		}
		out["urn:zitadel:iam:org:project:roles"] = roles
	}
	for k, v := range u.Extra {
		out[k] = v
	}
	return out
}

func (p *Provider) sign(claims map[string]any) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: p.keyID}},
		(&jose.SignerOptions{}).WithType("JWT"),
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
