package oidcauth_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vuongtlt13/oidcauth"
	"github.com/vuongtlt13/oidcauth/oidctest"
)

const (
	clientID     = "client-1"
	clientSecret = "secret-1"
	cookieSecret = "0123456789abcdef0123456789abcdef"
)

func newClient(t *testing.T, op *oidctest.Provider, mutate ...func(*oidcauth.Config)) *oidcauth.Client {
	t.Helper()
	cfg := oidcauth.Config{
		Issuer:       op.Issuer(),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://app.example.com/api/v1/auth/oidc/callback",
		CookieSecret: cookieSecret,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	c, err := oidcauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

var alice = oidctest.User{
	Subject:       "user-alice",
	Email:         "Alice@Example.com",
	EmailVerified: true,
	Name:          "Alice",
	Roles:         []string{"admin"},
	UserInfoOnly:  map[string]any{"preferred_username": "alice"},
}

func TestLoginRoundTrip(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)

	authURL, cookie, err := c.Start(ctx, oidcauth.WithReturnTo("/jobs?page=2"))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.MaxAge <= 0 {
		t.Fatalf("flow cookie must be HttpOnly+Secure with MaxAge, got %+v", cookie)
	}
	query := op.Authorize(t, authURL, alice)
	if got := c.CookieNameFor(query.Get("state")); got != cookie.Name {
		t.Fatalf("cookie name = %q, want %q", got, cookie.Name)
	}

	res, err := c.Finish(ctx, query, cookie.Value)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	id := res.Identity
	if id.Issuer != op.Issuer() || id.Subject != "user-alice" {
		t.Fatalf("iss/sub = %q/%q", id.Issuer, id.Subject)
	}
	if id.Email != "Alice@Example.com" || !id.EmailVerified || id.Name != "Alice" {
		t.Fatalf("profile = %+v", id)
	}
	if id.PreferredUsername != "alice" {
		t.Fatalf("userinfo-only claim not merged: %q", id.PreferredUsername)
	}
	if !id.HasRole("admin") || len(id.Roles) != 1 {
		t.Fatalf("roles = %v", id.Roles)
	}
	if id.Tokens.IDToken == "" || id.Tokens.AccessToken == "" {
		t.Fatalf("tokens missing")
	}
	if res.ReturnTo != "/jobs?page=2" {
		t.Fatalf("returnTo = %q", res.ReturnTo)
	}
}

func TestFinishRejectsStateMismatchAndReplay(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)

	authURL, cookie, _ := c.Start(ctx)
	query := op.Authorize(t, authURL, alice)

	// Cookie from another login flow.
	_, otherCookie, _ := c.Start(ctx)
	if _, err := c.Finish(ctx, query, otherCookie.Value); !errors.Is(err, oidcauth.ErrInvalidState) {
		t.Fatalf("foreign cookie: err = %v, want ErrInvalidState", err)
	}
	// Tampered state.
	bad := url.Values{"code": query["code"], "state": {"x" + query.Get("state")}}
	if _, err := c.Finish(ctx, bad, cookie.Value); !errors.Is(err, oidcauth.ErrInvalidState) {
		t.Fatalf("tampered state: err = %v", err)
	}
	// Missing cookie.
	if _, err := c.Finish(ctx, query, ""); !errors.Is(err, oidcauth.ErrInvalidState) {
		t.Fatalf("missing cookie: err = %v", err)
	}
	// Valid once, code cannot be replayed.
	if _, err := c.Finish(ctx, query, cookie.Value); err != nil {
		t.Fatalf("first finish: %v", err)
	}
	_, err := c.Finish(ctx, query, cookie.Value)
	if err == nil || !oidcauth.IsUserError(err) {
		t.Fatalf("replayed code: err = %v, want user error", err)
	}
}

func TestFinishRejectsCookieFromOtherSecret(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, clientID, clientSecret)
	a := newClient(t, op)
	b := newClient(t, op, func(c *oidcauth.Config) { c.CookieSecret = strings.Repeat("z", 32) })

	authURL, cookie, _ := a.Start(ctx)
	query := op.Authorize(t, authURL, alice)
	if _, err := b.Finish(ctx, query, cookie.Value); !errors.Is(err, oidcauth.ErrInvalidState) {
		t.Fatalf("err = %v, want ErrInvalidState", err)
	}
}

func TestFinishVerifiesIDToken(t *testing.T) {
	cases := map[string]func(map[string]any){
		"nonce":    func(c map[string]any) { c["nonce"] = "other" },
		"audience": func(c map[string]any) { c["aud"] = []string{"someone-else"}; c["azp"] = "someone-else" },
		"issuer":   func(c map[string]any) { c["iss"] = "https://evil.example.com" },
		"expired":  func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			op := oidctest.NewProvider(t, clientID, clientSecret)
			op.MutateIDToken = mutate
			c := newClient(t, op)
			authURL, cookie, _ := c.Start(ctx)
			query := op.Authorize(t, authURL, alice)
			_, err := c.Finish(ctx, query, cookie.Value)
			if err == nil || !oidcauth.IsUserError(err) {
				t.Fatalf("err = %v, want rejected id token", err)
			}
		})
	}
}

func TestFinishProviderError(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	authURL, cookie, _ := c.Start(ctx)
	state := op.Authorize(t, authURL, alice).Get("state")

	query := url.Values{"state": {state}, "error": {"access_denied"}, "error_description": {"no grant"}}
	_, err := c.Finish(ctx, query, cookie.Value)
	var pe *oidcauth.ProviderError
	if !errors.As(err, &pe) || pe.Code != "access_denied" || !oidcauth.IsUserError(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestStartWithExtraScopesAndPrompt(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	authURL, _, err := c.Start(context.Background(),
		oidcauth.WithExtraScopes("urn:zitadel:iam:org:id:42"),
		oidcauth.WithPrompt("login"),
	)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	q := mustQuery(t, authURL)
	if q.Get("scope") != "openid profile email urn:zitadel:iam:org:id:42" {
		t.Fatalf("scope = %q", q.Get("scope"))
	}
	if q.Get("prompt") != "login" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("query = %v", q)
	}
}

func TestProviderUnreachableIsNotUserError(t *testing.T) {
	c, err := oidcauth.New(oidcauth.Config{
		Issuer:       "http://127.0.0.1:1",
		ClientID:     clientID,
		RedirectURL:  "https://app.example.com/cb",
		CookieSecret: cookieSecret,
	})
	if err != nil {
		t.Fatalf("New must not contact the provider: %v", err)
	}
	_, _, err = c.Start(context.Background())
	if err == nil || oidcauth.IsUserError(err) {
		t.Fatalf("err = %v, want non-user error", err)
	}
}

func TestLogoutURL(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	u, err := c.LogoutURL(context.Background(), "idt", "https://app.example.com/", "s1")
	if err != nil {
		t.Fatalf("LogoutURL: %v", err)
	}
	q := mustQuery(t, u)
	if !strings.HasPrefix(u, op.Issuer()+"/oidc/v1/end_session?") ||
		q.Get("id_token_hint") != "idt" || q.Get("client_id") != clientID ||
		q.Get("post_logout_redirect_uri") != "https://app.example.com/" || q.Get("state") != "s1" {
		t.Fatalf("logout url = %s", u)
	}
}

func TestConfigValidate(t *testing.T) {
	_, err := oidcauth.New(oidcauth.Config{Issuer: "id.example.com", CookieSecret: "short"})
	if err == nil {
		t.Fatal("expected validation error")
	}
	for _, want := range []string{"issuer", "client id", "redirect url", "cookie secret"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	_, err = oidcauth.New(oidcauth.Config{
		Issuer: "https://id.example.com", ClientID: "c", RedirectURL: "https://a/cb",
		CookieSecret: cookieSecret, Scopes: []string{"profile"},
	})
	if err == nil || !strings.Contains(err.Error(), "openid") {
		t.Fatalf("err = %v, want openid scope error", err)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Query()
}
