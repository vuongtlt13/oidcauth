package oidcauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestSafeReturnTo(t *testing.T) {
	cases := map[string]string{
		"/jobs":                  "/jobs",
		"/jobs?x=1#top":          "/jobs?x=1#top",
		"":                       "/",
		"jobs":                   "/",
		"//evil.com":             "/",
		"/\\evil.com":            "/",
		"https://evil.com/":      "/",
		"/ok\r\nSet-Cookie: a=b": "/",
		"javascript:alert(1)":    "/",
	}
	for in, want := range cases {
		if got := SafeReturnTo(in, "/"); got != want {
			t.Errorf("SafeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMemoryTicketStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryTicketStore()
	ticket, _ := s.Put(ctx, "token-1", time.Minute)
	if v, err := s.Take(ctx, ticket); err != nil || v != "token-1" {
		t.Fatalf("Take = %q, %v", v, err)
	}
	if _, err := s.Take(ctx, ticket); !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("second Take err = %v, want single use", err)
	}

	now := time.Now()
	s.now = func() time.Time { return now }
	ticket, _ = s.Put(ctx, "token-2", time.Second)
	s.now = func() time.Time { return now.Add(2 * time.Second) }
	if _, err := s.Take(ctx, ticket); !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("expired Take err = %v", err)
	}
}

func TestDefaultRoleExtractor(t *testing.T) {
	got := DefaultRoleExtractor(map[string]any{
		"urn:zitadel:iam:org:project:roles":     map[string]any{"admin": map[string]any{}},
		"urn:zitadel:iam:org:project:123:roles": map[string]any{"viewer": map[string]any{}, "admin": map[string]any{}},
		"roles":                                 []any{"ignored-when-zitadel-present"},
	})
	if !reflect.DeepEqual(got, []string{"admin", "viewer"}) {
		t.Fatalf("zitadel roles = %v", got)
	}
	got = DefaultRoleExtractor(map[string]any{"roles": []any{"b", "a"}, "groups": []any{"a", "c"}})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("generic roles = %v", got)
	}
	if got := DefaultRoleExtractor(map[string]any{}); len(got) != 0 {
		t.Fatalf("empty = %v", got)
	}
}

func TestFlowCookieExpires(t *testing.T) {
	cfg := Config{CookieSecret: "0123456789abcdef0123456789abcdef"}.withDefaults()
	codec := newFlowCodec(cfg)
	now := time.Now()
	codec.now = func() time.Time { return now }
	ck, err := codec.encode(flow{State: "s", Nonce: "n", Verifier: "v"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.decode("s", ck.Value); err != nil {
		t.Fatalf("decode: %v", err)
	}
	codec.now = func() time.Time { return now.Add(cfg.FlowTTL + time.Second) }
	if _, err := codec.decode("s", ck.Value); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expired decode err = %v", err)
	}
}

func TestIdentityEmailVerifiedString(t *testing.T) {
	id := identityFromClaims(map[string]any{"sub": "1", "email_verified": "true"}, DefaultRoleExtractor)
	if !id.EmailVerified {
		t.Fatal(`"true" string must count as verified`)
	}
	if id.DisplayName() != "1" {
		t.Fatalf("DisplayName fallback = %q", id.DisplayName())
	}
}
