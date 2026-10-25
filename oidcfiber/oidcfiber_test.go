package oidcfiber_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/vuongtlt13/oidcauth"
	"github.com/vuongtlt13/oidcauth/oidcfiber"
	"github.com/vuongtlt13/oidcauth/oidctest"
)

func TestFiberLoginCallback(t *testing.T) {
	op := oidctest.NewProvider(t, "c1", "s1")
	client, err := oidcauth.New(oidcauth.Config{
		Issuer:       op.Issuer(),
		ClientID:     "c1",
		ClientSecret: "s1",
		RedirectURL:  "https://app.example.com/auth/callback",
		CookieSecret: strings.Repeat("k", 32),
	})
	if err != nil {
		t.Fatal(err)
	}

	var got *oidcauth.Result
	app := fiber.New()
	h := oidcfiber.New(client, oidcfiber.Options{
		OnSuccess: func(c *fiber.Ctx, res *oidcauth.Result) error {
			got = res
			return c.Redirect(oidcauth.SafeReturnTo(res.ReturnTo, "/"))
		},
		OnError: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusUnauthorized).SendString(err.Error())
		},
	})
	app.Get("/auth/login", h.Login)
	app.Get("/auth/callback", h.Callback)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/auth/login?redirect=/jobs", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusFound {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("login must not be cached")
	}
	flowCookie := findCookie(t, resp.Cookies(), "oidc_flow_")
	if !flowCookie.HttpOnly || !flowCookie.Secure || flowCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("flow cookie attrs = %+v", flowCookie)
	}

	query := op.Authorize(t, resp.Header.Get("Location"), oidctest.User{Subject: "u1", Email: "u1@example.com", EmailVerified: true})

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?"+query.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: flowCookie.Name, Value: flowCookie.Value})
	resp, err = app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback status = %d: %s", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != "/jobs" {
		t.Fatalf("redirect = %q", loc)
	}
	if got == nil || got.Identity.Subject != "u1" || got.Identity.Email != "u1@example.com" {
		t.Fatalf("result = %+v", got)
	}
	cleared := findCookie(t, resp.Cookies(), flowCookie.Name)
	if cleared.Value != "" {
		t.Fatalf("flow cookie must be cleared, got %+v", cleared)
	}

	// Replaying the same callback without a fresh flow fails.
	resp, err = app.Test(httptest.NewRequest(http.MethodGet, "/auth/callback?"+query.Encode(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("replay status = %d", resp.StatusCode)
	}
}

func TestDefaultErrorHandler(t *testing.T) {
	app := fiber.New()
	app.Get("/user", func(c *fiber.Ctx) error { return oidcfiber.DefaultErrorHandler(c, oidcauth.ErrInvalidState) })
	app.Get("/op", func(c *fiber.Ctx) error { return oidcfiber.DefaultErrorHandler(c, &url.Error{Op: "Get", Err: io.EOF}) })
	for path, want := range map[string]int{"/user": 401, "/op": 502} {
		resp, _ := app.Test(httptest.NewRequest(http.MethodGet, path, nil))
		if resp.StatusCode != want {
			t.Errorf("%s status = %d, want %d", path, resp.StatusCode, want)
		}
	}
}

func findCookie(t *testing.T, cookies []*http.Cookie, prefix string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, prefix) {
			return c
		}
	}
	t.Fatalf("cookie %q not found in %v", prefix, cookies)
	return nil
}
