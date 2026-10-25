package oidcauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vuongtlt13/oidcauth"
	"github.com/vuongtlt13/oidcauth/oidctest"
)

// login runs a full login and returns the result.
func login(t *testing.T, c *oidcauth.Client, op *oidctest.Provider, user oidctest.User, opts ...oidcauth.LoginOption) (*oidcauth.Result, error) {
	t.Helper()
	ctx := context.Background()
	authURL, cookie, err := c.Start(ctx, opts...)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return c.Finish(ctx, op.Authorize(t, authURL, user), cookie.Value)
}

func mustLogin(t *testing.T, c *oidcauth.Client, op *oidctest.Provider, user oidctest.User, opts ...oidcauth.LoginOption) *oidcauth.Identity {
	t.Helper()
	res, err := login(t, c, op, user, opts...)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return res.Identity
}

var bob = oidctest.User{
	Subject:       "user-bob",
	Email:         "bob@example.com",
	EmailVerified: true,
	Name:          "Bob",
	PhoneNumber:   "+84901234567",
	PhoneVerified: true,
	Address:       map[string]any{"locality": "Ha Noi", "country": "VN"},
	AMR:           []string{"pwd", "otp"},
	Extra:         map[string]any{"given_name": "Bob", "tenant": "t1"},
}

func TestScopesControlClaims(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)

	// Default scopes: openid profile email.
	id := mustLogin(t, c, op, bob)
	if got := op.LastAuthRequest().Get("scope"); got != "openid profile email" {
		t.Fatalf("scope = %q", got)
	}
	if !slices.Equal(id.Tokens.Scopes, []string{"openid", "profile", "email"}) || !id.Tokens.HasScope("email") {
		t.Fatalf("granted scopes = %v", id.Tokens.Scopes)
	}
	if id.Email != "bob@example.com" || id.GivenName != "Bob" || id.Claims["tenant"] != "t1" {
		t.Fatalf("profile/email claims missing: %+v", id)
	}
	if id.PhoneNumber != "" || id.Address != nil {
		t.Fatalf("phone/address released without their scopes: %+v", id)
	}

	// Extra scopes release phone and address.
	id = mustLogin(t, c, op, bob, oidcauth.WithExtraScopes(oidcauth.ScopePhone, oidcauth.ScopeAddress))
	if id.PhoneNumber != "+84901234567" || !id.PhoneNumberVerified {
		t.Fatalf("phone = %q/%v", id.PhoneNumber, id.PhoneNumberVerified)
	}
	if id.Address == nil || id.Address.Locality != "Ha Noi" || id.Address.Country != "VN" {
		t.Fatalf("address = %+v", id.Address)
	}
	if !id.Tokens.HasScope(oidcauth.ScopePhone) || !id.Tokens.HasScope(oidcauth.ScopeAddress) {
		t.Fatalf("granted scopes = %v", id.Tokens.Scopes)
	}
}

func TestGrantedScopesMayBeFewer(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	op.GrantScopes = func(requested []string) []string {
		return slices.DeleteFunc(slices.Clone(requested), func(s string) bool { return s == oidcauth.ScopeEmail })
	}
	c := newClient(t, op)
	id := mustLogin(t, c, op, bob)
	if id.Tokens.HasScope(oidcauth.ScopeEmail) || id.Email != "" {
		t.Fatalf("email granted? scopes=%v email=%q", id.Tokens.Scopes, id.Email)
	}
	if !id.Tokens.HasScope(oidcauth.ScopeProfile) {
		t.Fatalf("scopes = %v", id.Tokens.Scopes)
	}

	// Without `scope` in the token response the requested scopes are assumed.
	op.OmitScopeInResponse = true
	op.GrantScopes = nil
	id = mustLogin(t, c, op, bob, oidcauth.WithScopes(oidcauth.ScopeEmail))
	if !slices.Equal(id.Tokens.Scopes, []string{"openid", "email"}) {
		t.Fatalf("fallback scopes = %v", id.Tokens.Scopes)
	}
	if id.Name != "" {
		t.Fatalf("profile claim without profile scope: %q", id.Name)
	}
}

func TestAuthorizationRequestParameters(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	authURL, _, err := c.Start(context.Background(),
		oidcauth.WithScopes(oidcauth.ScopeEmail, oidcauth.ScopeOfflineAccess, oidcauth.ScopeEmail),
		oidcauth.WithPrompt(oidcauth.PromptLogin, oidcauth.PromptConsent),
		oidcauth.WithLoginHint("bob@example.com"),
		oidcauth.WithIDTokenHint("old-id-token"),
		oidcauth.WithMaxAge(90*time.Second),
		oidcauth.WithACRValues("urn:mfa", "urn:pwd"),
		oidcauth.WithUILocales("vi", "en"),
		oidcauth.WithClaimsLocales("vi"),
		oidcauth.WithDisplay(oidcauth.DisplayPopup),
		oidcauth.WithResponseMode(oidcauth.ResponseModeQuery),
		oidcauth.WithClaims(&oidcauth.ClaimsRequest{
			IDToken: map[string]*oidcauth.ClaimRequest{"email": {Essential: true}, "auth_time": nil},
		}),
		oidcauth.WithParam("organization", "acme"),
	)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	q := mustQuery(t, authURL)
	want := map[string]string{
		"scope":                 "openid email offline_access",
		"prompt":                "login consent",
		"login_hint":            "bob@example.com",
		"id_token_hint":         "old-id-token",
		"max_age":               "90",
		"acr_values":            "urn:mfa urn:pwd",
		"ui_locales":            "vi en",
		"claims_locales":        "vi",
		"display":               "popup",
		"response_mode":         "query",
		"organization":          "acme",
		"response_type":         "code",
		"code_challenge_method": "S256",
		"client_id":             clientID,
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	var claims map[string]map[string]any
	if err := json.Unmarshal([]byte(q.Get("claims")), &claims); err != nil {
		t.Fatalf("claims param %q: %v", q.Get("claims"), err)
	}
	if v, ok := claims["id_token"]["auth_time"]; !ok || v != nil {
		t.Errorf("claims auth_time = %v (present %v), want null", v, ok)
	}
	if email, _ := claims["id_token"]["email"].(map[string]any); email["essential"] != true {
		t.Errorf("claims email = %v", claims["id_token"]["email"])
	}
}

func TestStartRejectsInvalidOptions(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	ctx := context.Background()
	for name, opt := range map[string]oidcauth.LoginOption{
		"reserved state":    oidcauth.WithParam("state", "x"),
		"reserved nonce":    oidcauth.WithParam("nonce", "x"),
		"reserved scope":    oidcauth.WithParam("scope", "x"),
		"fragment mode":     oidcauth.WithResponseMode("fragment"),
		"negative max_age":  oidcauth.WithMaxAge(-time.Second),
		"reserved redirect": oidcauth.WithParam("redirect_uri", "https://evil"),
	} {
		if _, _, err := c.Start(ctx, opt); err == nil {
			t.Errorf("%s: Start succeeded", name)
		}
	}
}

func TestMaxAgeChecksAuthTime(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)

	recent := bob
	recent.AuthTime = time.Now().Add(-time.Minute)
	id := mustLogin(t, c, op, recent, oidcauth.WithMaxAge(5*time.Minute))
	if id.AuthTime.Unix() != recent.AuthTime.Unix() {
		t.Fatalf("auth_time = %v, want %v", id.AuthTime, recent.AuthTime)
	}

	stale := bob
	stale.AuthTime = time.Now().Add(-time.Hour)
	if _, err := login(t, c, op, stale, oidcauth.WithMaxAge(5*time.Minute)); err == nil || !oidcauth.IsUserError(err) {
		t.Fatalf("stale auth_time: err = %v, want user error", err)
	}
	// Without max_age the same login is fine.
	if _, err := login(t, c, op, stale); err != nil {
		t.Fatalf("no max_age: %v", err)
	}

	// max_age from Config, and auth_time is then required.
	c = newClient(t, op, func(cfg *oidcauth.Config) { cfg.MaxAge = 10 * time.Minute })
	op.MutateIDToken = func(claims map[string]any) { delete(claims, "auth_time") }
	_, err := login(t, c, op, bob)
	if err == nil || !oidcauth.IsUserError(err) {
		t.Fatalf("missing auth_time: err = %v, want user error", err)
	}
	if got := op.LastAuthRequest().Get("max_age"); got != "600" {
		t.Fatalf("max_age = %q", got)
	}
}

func TestRequireACR(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op, func(cfg *oidcauth.Config) {
		cfg.ACRValues = []string{"urn:mfa"}
		cfg.RequireACR = true
	})

	id := mustLogin(t, c, op, bob) // provider echoes the first acr_values
	if id.ACR != "urn:mfa" || !slices.Equal(id.AMR, []string{"pwd", "otp"}) || id.SessionID == "" {
		t.Fatalf("acr/amr/sid = %q/%v/%q", id.ACR, id.AMR, id.SessionID)
	}

	weak := bob
	weak.ACR = "urn:pwd"
	if _, err := login(t, c, op, weak); err == nil || !oidcauth.IsUserError(err) {
		t.Fatalf("weak acr: err = %v, want user error", err)
	}
	// A per-request override is enforced too.
	if _, err := login(t, c, op, weak, oidcauth.WithACRValues("urn:pwd")); err != nil {
		t.Fatalf("override acr: %v", err)
	}
	// Without RequireACR acr_values is only a hint.
	c = newClient(t, op, func(cfg *oidcauth.Config) { cfg.ACRValues = []string{"urn:mfa"} })
	if _, err := login(t, c, op, weak); err != nil {
		t.Fatalf("hint only: %v", err)
	}
}

func TestFinishRejectsIssuerMixUp(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	authURL, cookie, _ := c.Start(ctx)
	query := op.Authorize(t, authURL, bob)
	query.Set("iss", "https://evil.example.com")
	if _, err := c.Finish(ctx, query, cookie.Value); err == nil || !oidcauth.IsUserError(err) {
		t.Fatalf("err = %v, want user error", err)
	}
	// iss is optional (RFC 9207 only when the provider supports it).
	authURL, cookie, _ = c.Start(ctx)
	query = op.Authorize(t, authURL, bob)
	query.Del("iss")
	if _, err := c.Finish(ctx, query, cookie.Value); err != nil {
		t.Fatalf("without iss: %v", err)
	}
}

func TestFormPostFlowCookie(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	_, cookie, err := c.Start(context.Background(), oidcauth.WithResponseMode(oidcauth.ResponseModeFormPost))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if cookie.SameSite != http.SameSiteNoneMode || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("cookie = %+v", cookie)
	}
}

func TestRefresh(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)

	// No offline_access, no refresh token.
	if id := mustLogin(t, c, op, bob); id.Tokens.RefreshToken != "" {
		t.Fatalf("refresh token without offline_access")
	}

	id := mustLogin(t, c, op, bob, oidcauth.WithExtraScopes(oidcauth.ScopeOfflineAccess))
	first := id.Tokens.RefreshToken
	if first == "" {
		t.Fatal("refresh token missing with offline_access")
	}
	res, err := c.Refresh(ctx, first)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.Tokens.AccessToken == "" || res.Tokens.AccessToken == id.Tokens.AccessToken {
		t.Fatalf("access token not renewed")
	}
	if res.Tokens.RefreshToken == "" || res.Tokens.RefreshToken == first {
		t.Fatalf("refresh token not rotated")
	}
	if !res.Tokens.HasScope(oidcauth.ScopeOfflineAccess) || !res.Tokens.HasScope(oidcauth.ScopeEmail) {
		t.Fatalf("refreshed scopes = %v", res.Tokens.Scopes)
	}
	if res.Identity == nil || res.Identity.Subject != bob.Subject || res.Identity.Email != bob.Email {
		t.Fatalf("refreshed identity = %+v", res.Identity)
	}
	if res.Identity.Tokens.IDToken == "" {
		t.Fatalf("refreshed identity lacks tokens")
	}

	// A rotated refresh token is single use.
	if _, err := c.Refresh(ctx, first); err == nil || !oidcauth.IsUserError(err) {
		t.Fatalf("reused refresh token: err = %v, want user error", err)
	}
	if _, err := c.Refresh(ctx, ""); err == nil || !oidcauth.IsUserError(err) {
		t.Fatalf("empty refresh token: err = %v", err)
	}

	// Providers may omit the ID token on refresh.
	op.RefreshWithoutIDToken = true
	res, err = c.Refresh(ctx, res.Tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh without id_token: %v", err)
	}
	if res.Identity != nil || res.Tokens.IDToken != "" || res.Tokens.AccessToken == "" {
		t.Fatalf("result = %+v", res)
	}
}

func TestRefreshRejectsForgedIDToken(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	id := mustLogin(t, c, op, bob, oidcauth.WithExtraScopes(oidcauth.ScopeOfflineAccess))
	op.MutateIDToken = func(claims map[string]any) { claims["aud"] = []string{"other"}; claims["azp"] = "other" }
	if _, err := c.Refresh(context.Background(), id.Tokens.RefreshToken); err == nil || !oidcauth.IsUserError(err) {
		t.Fatalf("err = %v, want rejected id token", err)
	}
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	id := mustLogin(t, c, op, bob, oidcauth.WithExtraScopes(oidcauth.ScopeOfflineAccess))

	if err := c.Revoke(ctx, id.Tokens.RefreshToken, oidcauth.TokenTypeHintRefreshToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !slices.Contains(op.Revoked(), id.Tokens.RefreshToken) {
		t.Fatalf("revoked = %v", op.Revoked())
	}
	if _, err := c.Refresh(ctx, id.Tokens.RefreshToken); err == nil {
		t.Fatal("refresh with a revoked token succeeded")
	}
}

func TestUserInfo(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	id := mustLogin(t, c, op, alice)

	claims, err := c.UserInfo(ctx, id.Tokens.AccessToken, alice.Subject)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if claims["sub"] != alice.Subject || claims["email"] != alice.Email || claims["preferred_username"] != "alice" {
		t.Fatalf("claims = %v", claims)
	}
	if _, err := c.UserInfo(ctx, id.Tokens.AccessToken, "someone-else"); err == nil {
		t.Fatal("userinfo for another subject accepted")
	}
	if _, err := c.UserInfo(ctx, "bogus", alice.Subject); err == nil {
		t.Fatal("bogus access token accepted")
	}
}

func TestSkipUserInfo(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op, func(cfg *oidcauth.Config) { cfg.SkipUserInfo = true })
	id := mustLogin(t, c, op, alice)
	if id.PreferredUsername != "" || id.Email != alice.Email {
		t.Fatalf("identity = %+v", id)
	}
}

func TestLogoutURLOptions(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op, func(cfg *oidcauth.Config) { cfg.PostLogoutRedirectURL = "https://app.example.com/bye" })
	u, err := c.LogoutURL(context.Background(), "", "", "",
		oidcauth.WithLogoutHint("bob@example.com"), oidcauth.WithLogoutUILocales("vi", "en"))
	if err != nil {
		t.Fatalf("LogoutURL: %v", err)
	}
	q := mustQuery(t, u)
	if q.Get("logout_hint") != "bob@example.com" || q.Get("ui_locales") != "vi en" ||
		q.Get("post_logout_redirect_uri") != "https://app.example.com/bye" || q.Has("id_token_hint") || q.Has("state") {
		t.Fatalf("logout url = %s", u)
	}
}

func TestVerifyLogoutToken(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)

	lt, err := c.VerifyLogoutToken(ctx, op.LogoutToken("user-bob", "sid-1", nil))
	if err != nil {
		t.Fatalf("VerifyLogoutToken: %v", err)
	}
	if lt.Issuer != op.Issuer() || lt.Subject != "user-bob" || lt.SessionID != "sid-1" || lt.JWTID == "" ||
		lt.IssuedAt.IsZero() || lt.Expiry.Before(time.Now()) {
		t.Fatalf("logout token = %+v", lt)
	}
	if _, err := c.VerifyLogoutToken(ctx, op.LogoutToken("", "sid-only", nil)); err != nil {
		t.Fatalf("sid only: %v", err)
	}
	if _, err := c.VerifyLogoutToken(ctx, op.LogoutToken("sub-only", "", nil)); err != nil {
		t.Fatalf("sub only: %v", err)
	}

	other := oidctest.NewProvider(t, clientID, clientSecret)
	cases := map[string]string{
		"no event":       op.LogoutToken("u", "", func(c map[string]any) { delete(c, "events") }),
		"event not obj":  op.LogoutToken("u", "", func(c map[string]any) { c["events"] = map[string]any{oidcauth.BackChannelLogoutEvent: "x"} }),
		"nonce":          op.LogoutToken("u", "", func(c map[string]any) { c["nonce"] = "n" }),
		"audience":       op.LogoutToken("u", "", func(c map[string]any) { c["aud"] = []string{"other"} }),
		"issuer":         op.LogoutToken("u", "", func(c map[string]any) { c["iss"] = "https://evil.example.com" }),
		"expired":        op.LogoutToken("u", "", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"future iat":     op.LogoutToken("u", "", func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }),
		"no jti":         op.LogoutToken("u", "", func(c map[string]any) { delete(c, "jti") }),
		"no sub nor sid": op.LogoutToken("", "", nil),
		"foreign key":    other.LogoutToken("u", "", func(c map[string]any) { c["iss"] = op.Issuer() }),
		"garbage":        "a.b.c",
	}
	for name, raw := range cases {
		if _, err := c.VerifyLogoutToken(ctx, raw); !errors.Is(err, oidcauth.ErrInvalidLogoutToken) {
			t.Errorf("%s: err = %v, want ErrInvalidLogoutToken", name, err)
		}
	}
}

func TestClientAuthMethods(t *testing.T) {
	ctx := context.Background()

	t.Run("client_secret_basic", func(t *testing.T) {
		op := oidctest.NewProvider(t, clientID, clientSecret)
		c := newClient(t, op)
		mustLogin(t, c, op, bob)
		if op.LastClientAuth() != oidcauth.AuthMethodClientSecretBasic {
			t.Fatalf("auth = %q", op.LastClientAuth())
		}
	})

	t.Run("client_secret_post", func(t *testing.T) {
		op := oidctest.NewProvider(t, clientID, clientSecret)
		c := newClient(t, op, func(cfg *oidcauth.Config) { cfg.TokenEndpointAuthMethod = oidcauth.AuthMethodClientSecretPost })
		id := mustLogin(t, c, op, bob, oidcauth.WithExtraScopes(oidcauth.ScopeOfflineAccess))
		if op.LastClientAuth() != oidcauth.AuthMethodClientSecretPost {
			t.Fatalf("auth = %q", op.LastClientAuth())
		}
		if _, err := c.Refresh(ctx, id.Tokens.RefreshToken); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if op.LastClientAuth() != oidcauth.AuthMethodClientSecretPost {
			t.Fatalf("refresh auth = %q", op.LastClientAuth())
		}
	})

	t.Run("none", func(t *testing.T) {
		op := oidctest.NewProvider(t, clientID, "")
		c := newClient(t, op, func(cfg *oidcauth.Config) { cfg.ClientSecret = "" })
		mustLogin(t, c, op, bob)
		if op.LastClientAuth() != oidcauth.AuthMethodNone {
			t.Fatalf("auth = %q", op.LastClientAuth())
		}
	})

	t.Run("private_key_jwt", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		op := oidctest.NewProvider(t, clientID, "")
		op.ClientPublicKey = &key.PublicKey
		c := newClient(t, op, func(cfg *oidcauth.Config) {
			cfg.ClientSecret = ""
			cfg.ClientKey = keyPEM
			cfg.ClientKeyID = "key-1"
		})
		id := mustLogin(t, c, op, bob, oidcauth.WithExtraScopes(oidcauth.ScopeOfflineAccess))
		if op.LastClientAuth() != oidcauth.AuthMethodPrivateKeyJWT {
			t.Fatalf("auth = %q", op.LastClientAuth())
		}
		res, err := c.Refresh(ctx, id.Tokens.RefreshToken)
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if err := c.Revoke(ctx, res.Tokens.RefreshToken, oidcauth.TokenTypeHintRefreshToken); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if op.LastClientAuth() != oidcauth.AuthMethodPrivateKeyJWT {
			t.Fatalf("revoke auth = %q", op.LastClientAuth())
		}

		// A key the provider does not know is rejected.
		otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		op.ClientPublicKey = &otherKey.PublicKey
		if _, err := login(t, c, op, bob); err == nil || !oidcauth.IsUserError(err) {
			t.Fatalf("wrong key: err = %v", err)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		op := oidctest.NewProvider(t, clientID, clientSecret)
		c := newClient(t, op, func(cfg *oidcauth.Config) { cfg.ClientSecret = "wrong" })
		if _, err := login(t, c, op, bob); err == nil || !oidcauth.IsUserError(err) {
			t.Fatalf("err = %v, want user error", err)
		}
	})
}

func TestDiscovery(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op, func(cfg *oidcauth.Config) {
		cfg.DiscoveryURL = op.Issuer() + "/.well-known/openid-configuration"
	})
	d, err := c.Discovery(context.Background())
	if err != nil {
		t.Fatalf("Discovery: %v", err)
	}
	if d.Issuer != op.Issuer() || !slices.Contains(d.ScopesSupported, oidcauth.ScopeOfflineAccess) ||
		!d.BackChannelLogoutSupported || d.RevocationEndpoint == "" {
		t.Fatalf("discovery = %+v", d)
	}
}

func TestConfigValidateClientAuth(t *testing.T) {
	base := func() oidcauth.Config {
		return oidcauth.Config{
			Issuer: "https://id.example.com", ClientID: "c", RedirectURL: "https://a/cb", CookieSecret: cookieSecret,
		}
	}
	cases := map[string]struct {
		mutate func(*oidcauth.Config)
		want   string
	}{
		"secret and key":      {func(c *oidcauth.Config) { c.ClientSecret = "s"; c.ClientKey = []byte("k"); c.ClientKeyID = "1" }, "not both"},
		"key without id":      {func(c *oidcauth.Config) { c.ClientKey = []byte("k") }, "key id"},
		"basic without":       {func(c *oidcauth.Config) { c.TokenEndpointAuthMethod = oidcauth.AuthMethodClientSecretBasic }, "client secret"},
		"post without":        {func(c *oidcauth.Config) { c.TokenEndpointAuthMethod = oidcauth.AuthMethodClientSecretPost }, "client secret"},
		"jwt without key":     {func(c *oidcauth.Config) { c.TokenEndpointAuthMethod = oidcauth.AuthMethodPrivateKeyJWT }, "client key"},
		"none with secret":    {func(c *oidcauth.Config) { c.TokenEndpointAuthMethod = oidcauth.AuthMethodNone; c.ClientSecret = "s" }, "none"},
		"unknown method":      {func(c *oidcauth.Config) { c.TokenEndpointAuthMethod = "tls_client_auth" }, "unsupported"},
		"negative max age":    {func(c *oidcauth.Config) { c.MaxAge = -time.Second }, "max age"},
		"require acr no vals": {func(c *oidcauth.Config) { c.RequireACR = true }, "acr"},
		"relative discovery":  {func(c *oidcauth.Config) { c.DiscoveryURL = "/.well-known" }, "discovery url"},
	}
	for name, tc := range cases {
		cfg := base()
		tc.mutate(&cfg)
		if _, err := oidcauth.New(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	if _, err := oidcauth.New(base()); err != nil {
		t.Fatalf("public client config: %v", err)
	}
}
