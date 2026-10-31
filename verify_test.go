package oidcauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vuongtlt13/oidcauth"
	"github.com/vuongtlt13/oidcauth/oidctest"
)

const appID = "native-app-1"

func idToken(op *oidctest.Provider, mutate func(map[string]any)) string {
	now := time.Now().Unix()
	claims := map[string]any{
		"iss":            op.Issuer(),
		"sub":            "user-alice",
		"aud":            []string{appID},
		"azp":            appID,
		"iat":            now,
		"exp":            now + 3600,
		"email":          "alice@example.com",
		"email_verified": "true", // Sign in with Apple sends a string
		"name":           "Alice",
		"sid":            "sid-1",
	}
	if mutate != nil {
		mutate(claims)
	}
	return op.Sign(claims)
}

func TestVerifyIDTokenOfAnotherClient(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	raw := idToken(op, func(m map[string]any) { m["nonce"] = "n-1" })

	identity, err := c.VerifyIDToken(context.Background(), raw,
		oidcauth.WithAudience(appID), oidcauth.WithNonce("n-1"), oidcauth.WithTokenMaxAge(5*time.Minute))
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if identity.Issuer != op.Issuer() || identity.Subject != "user-alice" {
		t.Fatalf("identity = %s/%s", identity.Issuer, identity.Subject)
	}
	if identity.Email != "alice@example.com" || !identity.EmailVerified || identity.SessionID != "sid-1" {
		t.Fatalf("identity claims = %+v", identity)
	}
	if identity.Tokens.IDToken != raw {
		t.Fatal("Tokens.IDToken must be the verified token")
	}
}

func TestVerifyIDTokenOfOwnLoginMergesUserInfo(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	tokens := mustLogin(t, c, op, alice).Tokens

	identity, err := c.VerifyIDToken(ctx, tokens.IDToken, oidcauth.WithAccessToken(tokens.AccessToken))
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if identity.PreferredUsername != "alice" {
		t.Fatalf("userinfo-only claim missing: %+v", identity)
	}
	// Without the access token, only the ID token claims.
	identity, err = c.VerifyIDToken(ctx, tokens.IDToken)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if identity.PreferredUsername != "" {
		t.Fatalf("preferred_username = %q, want empty", identity.PreferredUsername)
	}
}

func TestVerifyIDTokenRejects(t *testing.T) {
	now := time.Now().Unix()
	set := func(kv ...any) func(map[string]any) {
		return func(m map[string]any) {
			for i := 0; i < len(kv); i += 2 {
				m[kv[i].(string)] = kv[i+1]
			}
		}
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
		opts   []oidcauth.VerifyOption
	}{
		{"audience default client", set("aud", []string{clientID}, "azp", clientID), nil},
		{"audience", set("aud", []string{"other"}, "azp", "other"), nil},
		{"azp", set("aud", []string{appID, "other"}, "azp", "other"), nil},
		{"issuer", set("iss", "https://evil.example.com"), nil},
		{"expired", set("exp", now-3600), nil},
		{"iat in future", set("iat", now+3600), nil},
		{"nonce", set("nonce", "other"), []oidcauth.VerifyOption{oidcauth.WithNonce("n-1")}},
		{"nonce missing", nil, []oidcauth.VerifyOption{oidcauth.WithNonce("n-1")}},
		{"max age", set("iat", now-600), []oidcauth.VerifyOption{oidcauth.WithTokenMaxAge(5 * time.Minute)}},
		{"subject missing", set("sub", ""), nil},
	}
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := append([]oidcauth.VerifyOption{oidcauth.WithAudience(appID)}, tt.opts...)
			_, err := c.VerifyIDToken(context.Background(), idToken(op, tt.mutate), opts...)
			if err == nil || !oidcauth.IsUserError(err) {
				t.Fatalf("want a user error, got %v", err)
			}
		})
	}
}

func TestVerifyIDTokenRejectsForeignSignature(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	other := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	// Right issuer, another key.
	raw := other.Sign(map[string]any{
		"iss": op.Issuer(), "sub": "user-alice", "aud": []string{appID},
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := c.VerifyIDToken(context.Background(), raw, oidcauth.WithAudience(appID)); err == nil || !oidcauth.IsUserError(err) {
		t.Fatalf("want a user error, got %v", err)
	}
}

func TestVerifyIDTokenRejectsAccessTokenOfAnotherUser(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	tokens := mustLogin(t, c, op, alice).Tokens
	other := mustLogin(t, c, op, bob).Tokens
	// The fake provider issues no at_hash: userinfo answers for the wrong subject.
	if _, err := c.VerifyIDToken(context.Background(), tokens.IDToken, oidcauth.WithAccessToken(other.AccessToken)); err == nil {
		t.Fatal("want an error for another user's access token")
	}
}

func TestVerifyIDTokenEmpty(t *testing.T) {
	op := oidctest.NewProvider(t, clientID, clientSecret)
	c := newClient(t, op)
	if _, err := c.VerifyIDToken(context.Background(), ""); err == nil || !oidcauth.IsUserError(err) {
		t.Fatalf("want a user error, got %v", err)
	}
}

func TestVerifyOnlyClient(t *testing.T) {
	ctx := context.Background()
	op := oidctest.NewProvider(t, appID, "")
	c, err := oidcauth.New(oidcauth.Config{Issuer: op.Issuer(), ClientID: appID, VerifyOnly: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.VerifyIDToken(ctx, idToken(op, nil)); err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if _, _, err := c.Start(ctx); !errors.Is(err, oidcauth.ErrVerifyOnly) {
		t.Fatalf("Start: want ErrVerifyOnly, got %v", err)
	}
	if _, err := c.Finish(ctx, nil, "cookie"); !errors.Is(err, oidcauth.ErrVerifyOnly) {
		t.Fatalf("Finish: want ErrVerifyOnly, got %v", err)
	}
	if _, err := oidcauth.New(oidcauth.Config{Issuer: op.Issuer(), ClientID: appID}); err == nil {
		t.Fatal("a login client still needs a redirect url and cookie secret")
	}
}
