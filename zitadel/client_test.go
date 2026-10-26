package zitadel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("case") {
		case "login":
			http.Redirect(w, r, "/ui/v2/login/login?authRequest=V2_1", http.StatusFound)
		case "error":
			http.Redirect(w, r, "http://api.test/cb?error=invalid_scope&state=s", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, "pat", nil)
	ctx := context.Background()

	id, loc, err := c.Authorize(ctx, srv.URL+"/oauth/v2/authorize?case=login")
	if err != nil || id != "V2_1" || loc != "" {
		t.Fatalf("login: id=%q loc=%q err=%v", id, loc, err)
	}

	// The client's error redirect, for the browser.
	id, loc, err = c.Authorize(ctx, srv.URL+"/oauth/v2/authorize?case=error")
	if err != nil || id != "" || loc != "http://api.test/cb?error=invalid_scope&state=s" {
		t.Fatalf("error: id=%q loc=%q err=%v", id, loc, err)
	}

	// Login V1 or a misconfigured instance renders a page instead.
	_, _, err = c.Authorize(ctx, srv.URL+"/oauth/v2/authorize?case=page")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("page: err = %v, want *APIError", err)
	}
}

func TestAuthRequestError(t *testing.T) {
	cases := []struct {
		err     error
		expired bool
	}{
		{&APIError{Status: 404, Message: "Errors.AuthRequest.NotFound"}, true},
		{&APIError{Status: 412, Message: "Errors.AuthRequest.AlreadyHandled (OIDC-1)"}, true},
		{&APIError{Status: 403, Message: "Errors.Token.Invalid"}, false},
	}
	for _, tc := range cases {
		if got := errors.Is(authRequestError(tc.err), ErrAuthRequestExpired); got != tc.expired {
			t.Errorf("%v: expired = %v, want %v", tc.err, got, tc.expired)
		}
	}
}

func TestAuthRequestOrgID(t *testing.T) {
	if got := (&AuthRequest{Scope: []string{"openid", "urn:zitadel:iam:org:id:42"}}).OrgID(); got != "42" {
		t.Errorf("OrgID = %q, want 42", got)
	}
	if got := (&AuthRequest{Scope: []string{"openid"}}).OrgID(); got != "" {
		t.Errorf("OrgID = %q, want empty", got)
	}
}
