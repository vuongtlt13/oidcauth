package zitadelfiber_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/vuongtlt13/oidcauth"
	"github.com/vuongtlt13/oidcauth/oidcfiber"
	"github.com/vuongtlt13/oidcauth/oidctest"
	"github.com/vuongtlt13/oidcauth/zitadel"
	"github.com/vuongtlt13/oidcauth/zitadel/zitadelfiber"
	"github.com/vuongtlt13/oidcauth/zitadel/zitadeltest"
)

// env is an app with the client's callback (oidcfiber) and the identity
// provider login (zitadelfiber) of the same client.
type env struct {
	app  *fiber.App
	fake *zitadeltest.Server
	// result of the last successful login, err of the last failure.
	result *oidcauth.Result
	err    error
}

func newEnv(t *testing.T) *env {
	t.Helper()
	op := oidctest.NewProvider(t, "c1", "s1")
	fake := zitadeltest.New(t, op)
	client, err := oidcauth.New(oidcauth.Config{
		Issuer:       op.Issuer(),
		ClientID:     "c1",
		ClientSecret: "s1",
		RedirectURL:  "http://api.test/auth/callback",
		CookieSecret: strings.Repeat("k", 32),
		CookiePath:   "/auth/",
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{app: fiber.New(), fake: fake}
	onError := func(c *fiber.Ctx, err error) error {
		e.err = err
		return c.Redirect("/login?error=1", fiber.StatusFound)
	}
	web := oidcfiber.New(client, oidcfiber.Options{
		OnSuccess: func(c *fiber.Ctx, res *oidcauth.Result) error {
			e.result = res
			return c.Redirect(oidcauth.SafeReturnTo(res.ReturnTo, "/"), fiber.StatusFound)
		},
		OnError: onError,
	})
	login := zitadel.NewIDPLogin(zitadel.New(fake.URL, zitadeltest.Token, fake.HTTPClient()), zitadeltest.IDPID)
	idp := zitadelfiber.New(client, login, zitadelfiber.Options{
		Tickets:     oidcauth.NewMemoryTicketStore(),
		CallbackURL: "http://api.test/auth/google/idp/callback",
		OnError:     onError,
	})
	e.app.Get("/auth/callback", web.Callback)
	e.app.Get("/auth/google/login", idp.Login)
	e.app.Get("/auth/google/idp/callback", idp.Callback)
	return e
}

// start runs the login route and returns its redirect and the cookies the
// browser keeps.
func (e *env) start(t *testing.T, returnTo string) (*url.URL, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/google/login?redirect="+url.QueryEscape(returnTo), nil)
	resp, err := e.app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusFound {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("login must not be cached")
	}
	var cookies []*http.Cookie
	for _, c := range resp.Cookies() {
		if c.Value != "" {
			cookies = append(cookies, c)
		}
	}
	return parse(t, resp.Header.Get("Location")), cookies
}

// follow sends the browser to an API URL with cookies and returns the
// redirect.
func (e *env) follow(t *testing.T, raw string, cookies []*http.Cookie) *url.URL {
	t.Helper()
	u := parse(t, raw)
	if u.Host != "" && u.Host != "api.test" {
		t.Fatalf("leaves the API: %s", raw)
	}
	req := httptest.NewRequest(http.MethodGet, u.RequestURI(), nil)
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	resp, err := e.app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusFound {
		t.Fatalf("%s: status = %d", u.Path, resp.StatusCode)
	}
	return parse(t, resp.Header.Get("Location"))
}

// login runs the whole login: login route → identity provider (the browser
// only sees its page) → Zitadel → idp callback → client callback, and
// returns the final redirect.
func (e *env) login(t *testing.T, returnTo string) *url.URL {
	t.Helper()
	loc, cookies := e.start(t, returnTo)
	if !strings.HasPrefix(loc.String(), zitadeltest.IDPAuthURL) {
		t.Fatalf("browser must go straight to the identity provider, got %s", loc)
	}
	loc = e.follow(t, e.fake.SuccessRedirect(), cookies)
	if loc.Path != "/auth/callback" {
		return loc // error
	}
	return e.follow(t, loc.String(), cookies)
}

func parse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestLinkedAccountLogsIn(t *testing.T) {
	e := newEnv(t)
	e.fake.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: zitadeltest.DefaultOrgID, Email: "a@example.com"}
	e.fake.External = zitadeltest.External{ID: "g-1", Email: "a@gmail.com", Verified: true, LinkedTo: "u1"}

	loc := e.login(t, "/jobs")
	if loc.String() != "/jobs" {
		t.Fatalf("redirect = %s, err = %v", loc, e.err)
	}
	if e.fake.SessionUser != "u1" {
		t.Fatalf("session user = %q", e.fake.SessionUser)
	}
	if e.result == nil || e.result.Identity.Subject != "u1" {
		t.Fatalf("the identity must be the Zitadel user, got %+v", e.result)
	}
}

func TestAutoLinksByVerifiedEmail(t *testing.T) {
	e := newEnv(t)
	e.fake.AutoLinking = zitadel.AutoLinkingEmail
	e.fake.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: zitadeltest.DefaultOrgID, Email: "A@Gmail.com"}
	e.fake.External = zitadeltest.External{ID: "g-1", Email: "a@gmail.com", Verified: true}

	if loc := e.login(t, "/"); loc.String() != "/" {
		t.Fatalf("redirect = %s, err = %v", loc, e.err)
	}
	if e.fake.Links["u1"] != "g-1" || e.fake.SessionUser != "u1" {
		t.Fatalf("links = %v, session user = %q", e.fake.Links, e.fake.SessionUser)
	}
}

func TestAutoCreates(t *testing.T) {
	for name, tc := range map[string]struct {
		scope []string
		org   string
	}{
		"in the requested org": {[]string{"openid", "urn:zitadel:iam:org:id:org-customer"}, "org-customer"},
		"in the default org":   {nil, zitadeltest.DefaultOrgID},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.fake.IsAutoCreation = true
			e.fake.AuthRequestScope = tc.scope
			e.fake.External = zitadeltest.External{ID: "g-1", Email: "new@gmail.com", Verified: true, GivenName: "An", FamilyName: "Nguyen"}

			if loc := e.login(t, "/"); loc.String() != "/" {
				t.Fatalf("redirect = %s, err = %v", loc, e.err)
			}
			if len(e.fake.Created) != 1 || e.fake.Created[0]["organizationId"] != tc.org {
				t.Fatalf("created = %v", e.fake.Created)
			}
			if e.fake.SessionUser != zitadeltest.NewUserID {
				t.Fatalf("session user = %q", e.fake.SessionUser)
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]struct {
		setup func(*zitadeltest.Server)
		want  error
		// session: Zitadel checks the project grant when completing the auth
		// request, after the session exists.
		session bool
	}{
		"not linked, no auto options": {
			setup: func(f *zitadeltest.Server) {
				f.External = zitadeltest.External{ID: "g-1", Email: "a@gmail.com", Verified: true}
			},
			want: zitadel.ErrNotLinked,
		},
		"auto-link needs a verified email": {
			setup: func(f *zitadeltest.Server) {
				f.AutoLinking = zitadel.AutoLinkingEmail
				f.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: zitadeltest.DefaultOrgID, Email: "a@gmail.com"}
				f.External = zitadeltest.External{ID: "g-1", Email: "a@gmail.com"}
			},
			want: zitadel.ErrNotLinked,
		},
		"auto-link with several matches": {
			setup: func(f *zitadeltest.Server) {
				f.AutoLinking = zitadel.AutoLinkingEmail
				f.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: zitadeltest.DefaultOrgID, Email: "a@gmail.com"}
				f.Users["u2"] = &zitadeltest.User{ID: "u2", OrgID: "org-other", Email: "a@gmail.com"}
				f.External = zitadeltest.External{ID: "g-1", Email: "a@gmail.com", Verified: true}
			},
			want: zitadel.ErrNotLinked,
		},
		"auto-link into an org without the idp": {
			setup: func(f *zitadeltest.Server) {
				f.AutoLinking = zitadel.AutoLinkingEmail
				f.Orgs["org-closed"] = &zitadeltest.Org{AllowExternalIDP: true}
				f.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: "org-closed", Email: "a@gmail.com"}
				f.External = zitadeltest.External{ID: "g-1", Email: "a@gmail.com", Verified: true}
			},
			want: zitadel.ErrNotAllowed,
		},
		"user outside the requested org": {
			setup: func(f *zitadeltest.Server) {
				f.AuthRequestScope = []string{"urn:zitadel:iam:org:id:org-customer"}
				f.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: zitadeltest.DefaultOrgID}
				f.External = zitadeltest.External{ID: "g-1", LinkedTo: "u1"}
			},
			want: zitadel.ErrNotAllowed,
		},
		"auto-create without names": {
			setup: func(f *zitadeltest.Server) {
				f.IsAutoCreation = true
				f.External = zitadeltest.External{ID: "g-1", Email: "a@gmail.com", Verified: true}
			},
			want: zitadel.ErrNotLinked,
		},
		"inactive user": {
			setup: func(f *zitadeltest.Server) {
				f.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: zitadeltest.DefaultOrgID, State: zitadel.UserStateInactive}
				f.External = zitadeltest.External{ID: "g-1", LinkedTo: "u1"}
			},
			want: zitadel.ErrUserInactive,
		},
		"org forces MFA": {
			setup: func(f *zitadeltest.Server) {
				f.Orgs[zitadeltest.DefaultOrgID].ForceMFA = true
				f.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: zitadeltest.DefaultOrgID}
				f.External = zitadeltest.External{ID: "g-1", LinkedTo: "u1"}
			},
			want: zitadel.ErrMFARequired,
		},
		"no project grant": {
			setup: func(f *zitadeltest.Server) {
				f.CallbackError = "Errors.User.GrantRequired (OIDC-foSyH49RvL)"
				f.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: zitadeltest.DefaultOrgID}
				f.External = zitadeltest.External{ID: "g-1", LinkedTo: "u1"}
			},
			want:    zitadel.ErrAccessDenied,
			session: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			tc.setup(e.fake)
			loc := e.login(t, "/")
			if loc.String() != "/login?error=1" || !errors.Is(e.err, tc.want) {
				t.Fatalf("redirect = %s, err = %v, want %v", loc, e.err, tc.want)
			}
			if !zitadel.IsUserError(e.err) {
				t.Fatalf("%v must be a user error", e.err)
			}
			if !tc.session && e.fake.SessionUser != "" {
				t.Fatalf("no session expected, got user %q", e.fake.SessionUser)
			}
		})
	}
}

func TestCancelledAtTheIdentityProvider(t *testing.T) {
	e := newEnv(t)
	_, cookies := e.start(t, "/")
	e.follow(t, e.fake.FailureRedirect("access_denied"), cookies)
	if !errors.Is(e.err, zitadel.ErrIntentFailed) {
		t.Fatalf("err = %v", e.err)
	}
}

func TestTicketIsSingleUse(t *testing.T) {
	e := newEnv(t)
	e.fake.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: zitadeltest.DefaultOrgID}
	e.fake.External = zitadeltest.External{ID: "g-1", LinkedTo: "u1"}
	_, cookies := e.start(t, "/")
	success := e.fake.SuccessRedirect()
	if loc := e.follow(t, success, cookies); loc.Path != "/auth/callback" {
		t.Fatalf("first use: %s, err = %v", loc, e.err)
	}
	e.follow(t, success, cookies)
	if !errors.Is(e.err, oidcauth.ErrInvalidState) {
		t.Fatalf("replay: err = %v", e.err)
	}
}

func TestForgedCallbackIsRejected(t *testing.T) {
	e := newEnv(t)
	e.follow(t, "http://api.test/auth/google/idp/callback?rq=forged&id=x&token=y", nil)
	if !errors.Is(e.err, oidcauth.ErrInvalidState) {
		t.Fatalf("err = %v", e.err)
	}
}

func TestCodeNeedsTheFlowCookie(t *testing.T) {
	// The client's callback still checks state, nonce and PKCE against the
	// flow cookie of the browser that started the login.
	e := newEnv(t)
	e.fake.Users["u1"] = &zitadeltest.User{ID: "u1", OrgID: zitadeltest.DefaultOrgID}
	e.fake.External = zitadeltest.External{ID: "g-1", LinkedTo: "u1"}
	_, cookies := e.start(t, "/")
	loc := e.follow(t, e.fake.SuccessRedirect(), cookies)
	if loc.Path != "/auth/callback" {
		t.Fatalf("redirect = %s, err = %v", loc, e.err)
	}
	e.follow(t, loc.String(), nil)
	if !errors.Is(e.err, oidcauth.ErrInvalidState) || e.result != nil {
		t.Fatalf("err = %v, result = %+v", e.err, e.result)
	}
}
