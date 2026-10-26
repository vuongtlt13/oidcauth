// Package zitadeltest is a fake Zitadel v2 API for the identity provider
// login (zitadel.IDPLogin), on top of an oidctest provider that issues the
// tokens: the authorization request gets a V2 auth request, and completing
// it returns the provider's code callback.
package zitadeltest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/vuongtlt13/oidcauth/oidctest"
)

// Fixed values of the fake.
const (
	Token         = "service-pat"
	IDPID         = "idp-google"
	AuthRequestID = "V2_auth-1"
	IntentID      = "intent-1"
	IntentToken   = "intent-token"
	DefaultOrgID  = "org-default"
	NewUserID     = "user-new"
	// IDPAuthURL is where StartIntent sends the browser (the fake Google).
	IDPAuthURL = "https://accounts.google.test/o/oauth2/auth"
)

// User is a Zitadel user of the fake.
type User struct {
	ID    string
	OrgID string
	Email string
	State string // defaults to USER_STATE_ACTIVE
	// OIDC is what the provider puts in the tokens of this user; Subject
	// defaults to ID.
	OIDC oidctest.User
}

// Org is the login policy of an organization.
type Org struct {
	AllowExternalIDP bool
	ForceMFA         bool
	// IDPs active at login, with linking allowed.
	IDPs []string
}

// External is the account the user logs in with at the identity provider.
type External struct {
	ID         string
	Email      string
	Verified   bool
	GivenName  string
	FamilyName string
	// LinkedTo is the Zitadel user the account is already linked to.
	LinkedTo string
}

// Server is the fake Zitadel API. Configure the fields before the login.
type Server struct {
	*httptest.Server
	OP *oidctest.Provider

	// Options of the identity provider IDPID, in the protojson shape.
	AutoLinking    string
	IsAutoCreation bool
	Users          map[string]*User
	Orgs           map[string]*Org
	External       External
	// AuthRequestScope is the scope of the auth request (an org scope
	// restricts the users).
	AuthRequestScope []string
	// CallbackError makes CreateCallback fail with this message.
	CallbackError string

	mu         sync.Mutex
	authURL    string
	successURL string
	failureURL string
	handled    bool
	consumed   bool
	// Links holds the external accounts linked by AddIDPLink: user → idp user.
	Links map[string]string
	// Created holds the CreateUser requests.
	Created []map[string]any
	// SessionUser is the user of the last session.
	SessionUser string
}

// New starts the fake for provider op; it is closed with t.Cleanup.
func New(t testing.TB, op *oidctest.Provider) *Server {
	t.Helper()
	s := &Server{
		OP:    op,
		Users: map[string]*User{},
		Orgs:  map[string]*Org{DefaultOrgID: {AllowExternalIDP: true, IDPs: []string{IDPID}}},
		Links: map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/idp_intents", s.startIntent)
	mux.HandleFunc("POST /v2/idp_intents/{id}", s.retrieveIntent)
	mux.HandleFunc("GET /v2/idps/{id}", s.idp)
	mux.HandleFunc("POST /v2/users", s.listUsers)
	mux.HandleFunc("GET /v2/users/{id}", s.getUser)
	mux.HandleFunc("POST /v2/users/{id}/links", s.addLink)
	mux.HandleFunc("POST /v2/users/new", s.createUser)
	mux.HandleFunc("POST /v2/organizations/_search", s.orgs)
	mux.HandleFunc("GET /v2/settings/login", s.loginSettings)
	mux.HandleFunc("GET /v2/settings/login/idps", s.activeIDPs)
	mux.HandleFunc("POST /v2/sessions", s.createSession)
	mux.HandleFunc("GET /v2/oidc/auth_requests/{id}", s.authRequest)
	mux.HandleFunc("POST /v2/oidc/auth_requests/{id}", s.createCallback)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+Token {
			apiError(w, http.StatusUnauthorized, "Errors.Token.Invalid")
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Server.Close)
	return s
}

// HTTPClient answers the provider's authorization endpoint like Zitadel
// with Login V2 (a redirect to the login UI with the auth request ID) and
// sends every other request to the fake API.
func (s *Server) HTTPClient() *http.Client {
	return &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/oauth/v2/authorize" {
			s.mu.Lock()
			s.authURL = r.URL.String()
			s.handled = false
			s.mu.Unlock()
			h := http.Header{}
			h.Set("Location", r.URL.Scheme+"://"+r.URL.Host+"/ui/v2/login/login?authRequest="+AuthRequestID)
			return &http.Response{StatusCode: http.StatusFound, Header: h, Body: http.NoBody, Request: r}, nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// SuccessRedirect is where Zitadel sends the browser after a succeeded
// login at the identity provider: the success URL with the intent.
func (s *Server) SuccessRedirect() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := url.Values{"id": {IntentID}, "token": {IntentToken}}
	if s.External.LinkedTo != "" {
		q.Set("user", s.External.LinkedTo)
	}
	return appendQuery(s.successURL, q)
}

// FailureRedirect is where Zitadel sends the browser after a failed login
// at the identity provider.
func (s *Server) FailureRedirect(code string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return appendQuery(s.failureURL, url.Values{"error": {code}, "error_description": {"failed"}})
}

func appendQuery(raw string, q url.Values) string {
	sep := "?"
	if strings.Contains(raw, "?") {
		sep = "&"
	}
	return raw + sep + q.Encode()
}

func (s *Server) startIntent(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDPID string `json:"idpId"`
		URLs  struct {
			SuccessURL string `json:"successUrl"`
			FailureURL string `json:"failureUrl"`
		} `json:"urls"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.IDPID != IDPID {
		apiError(w, http.StatusNotFound, "Errors.IDPConfig.NotExisting")
		return
	}
	s.mu.Lock()
	s.successURL, s.failureURL, s.consumed = in.URLs.SuccessURL, in.URLs.FailureURL, false
	s.mu.Unlock()
	writeJSON(w, map[string]any{"authUrl": IDPAuthURL + "?state=zitadel-state"})
}

func (s *Server) retrieveIntent(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"idpIntentToken"`
	}
	if !decode(w, r, &in) {
		return
	}
	if r.PathValue("id") != IntentID || in.Token != IntentToken {
		apiError(w, http.StatusPreconditionFailed, "Errors.Intent.InvalidToken")
		return
	}
	ext := s.External
	out := map[string]any{
		"idpInformation": map[string]any{"idpId": IDPID, "userId": ext.ID, "userName": ext.Email},
	}
	if ext.LinkedTo != "" {
		out["userId"] = ext.LinkedTo
	} else {
		email := map[string]any{"email": ext.Email}
		if ext.Verified {
			email["isVerified"] = true
		} else {
			email["sendCode"] = map[string]any{}
		}
		out["createUser"] = map[string]any{
			"username": ext.Email,
			"human": map[string]any{
				"profile":  map[string]any{"givenName": ext.GivenName, "familyName": ext.FamilyName},
				"email":    email,
				"idpLinks": []map[string]any{{"idpId": IDPID, "userId": ext.ID, "userName": ext.Email}},
			},
		}
	}
	writeJSON(w, out)
}

func (s *Server) idp(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"idp": map[string]any{"id": r.PathValue("id"), "config": map[string]any{
		"options": map[string]any{
			"isLinkingAllowed": true,
			"isAutoCreation":   s.IsAutoCreation,
			"autoLinking":      s.AutoLinking,
		},
	}}})
}

func (s *Server) user(u *User) map[string]any {
	state := u.State
	if state == "" {
		state = "USER_STATE_ACTIVE"
	}
	return map[string]any{"userId": u.ID, "state": state, "details": map[string]any{"resourceOwner": u.OrgID}}
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Queries []struct {
			EmailQuery *struct {
				EmailAddress string `json:"emailAddress"`
			} `json:"emailQuery"`
			OrganizationIDQuery *struct {
				OrganizationID string `json:"organizationId"`
			} `json:"organizationIdQuery"`
		} `json:"queries"`
	}
	if !decode(w, r, &in) {
		return
	}
	var email, org string
	for _, q := range in.Queries {
		if q.EmailQuery != nil {
			email = q.EmailQuery.EmailAddress
		}
		if q.OrganizationIDQuery != nil {
			org = q.OrganizationIDQuery.OrganizationID
		}
	}
	result := []map[string]any{}
	s.mu.Lock()
	for _, u := range s.Users {
		if strings.EqualFold(u.Email, email) && (org == "" || u.OrgID == org) {
			result = append(result, s.user(u))
		}
	}
	s.mu.Unlock()
	writeJSON(w, map[string]any{"result": result})
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	u, ok := s.Users[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		apiError(w, http.StatusNotFound, "Errors.User.NotFound")
		return
	}
	writeJSON(w, map[string]any{"user": s.user(u)})
}

func (s *Server) addLink(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDPLink struct {
			IDPID  string `json:"idpId"`
			UserID string `json:"userId"`
		} `json:"idpLink"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	s.Links[r.PathValue("id")] = in.IDPLink.UserID
	s.mu.Unlock()
	writeJSON(w, map[string]any{})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	in := map[string]any{}
	if !decode(w, r, &in) {
		return
	}
	org, _ := in["organizationId"].(string)
	s.mu.Lock()
	s.Created = append(s.Created, in)
	s.Users[NewUserID] = &User{ID: NewUserID, OrgID: org, Email: s.External.Email}
	s.Links[NewUserID] = s.External.ID // from human.idpLinks
	s.mu.Unlock()
	writeJSON(w, map[string]any{"id": NewUserID})
}

func (s *Server) orgs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"result": []map[string]any{{"id": DefaultOrgID}}})
}

func (s *Server) org(r *http.Request) *Org {
	if o, ok := s.Orgs[r.URL.Query().Get("ctx.orgId")]; ok {
		return o
	}
	return &Org{}
}

func (s *Server) loginSettings(w http.ResponseWriter, r *http.Request) {
	o := s.org(r)
	writeJSON(w, map[string]any{"settings": map[string]any{"allowExternalIdp": o.AllowExternalIDP, "forceMfa": o.ForceMFA}})
}

func (s *Server) activeIDPs(w http.ResponseWriter, r *http.Request) {
	list := []map[string]any{}
	for _, id := range s.org(r).IDPs {
		list = append(list, map[string]any{"id": id})
	}
	writeJSON(w, map[string]any{"identityProviders": list})
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Checks struct {
			User struct {
				UserID string `json:"userId"`
			} `json:"user"`
			IDPIntent struct {
				ID    string `json:"idpIntentId"`
				Token string `json:"idpIntentToken"`
			} `json:"idpIntent"`
		} `json:"checks"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	userID := in.Checks.User.UserID
	if in.Checks.IDPIntent.ID != IntentID || in.Checks.IDPIntent.Token != IntentToken || s.consumed {
		apiError(w, http.StatusPreconditionFailed, "Errors.Intent.NotSucceeded")
		return
	}
	// CheckIntent: the external account must belong to the session user.
	if s.External.LinkedTo != userID && s.Links[userID] != s.External.ID {
		apiError(w, http.StatusPreconditionFailed, "Errors.Intent.OtherUser")
		return
	}
	s.consumed = true
	s.SessionUser = userID
	writeJSON(w, map[string]any{"sessionId": "session-1", "sessionToken": "session-token"})
}

func (s *Server) authRequest(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.PathValue("id") != AuthRequestID || s.authURL == "" {
		apiError(w, http.StatusNotFound, "Errors.AuthRequest.NotFound")
		return
	}
	writeJSON(w, map[string]any{"authRequest": map[string]any{"id": AuthRequestID, "clientId": s.OP.ClientID, "scope": s.AuthRequestScope}})
}

func (s *Server) createCallback(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Session struct {
			ID    string `json:"sessionId"`
			Token string `json:"sessionToken"`
		} `json:"session"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.PathValue("id") != AuthRequestID || s.authURL == "":
		apiError(w, http.StatusNotFound, "Errors.AuthRequest.NotFound")
		return
	case s.handled:
		apiError(w, http.StatusPreconditionFailed, "Errors.AuthRequest.AlreadyHandled")
		return
	case in.Session.ID != "session-1" || in.Session.Token != "session-token":
		apiError(w, http.StatusPreconditionFailed, "Errors.Session.Token.Invalid")
		return
	case s.CallbackError != "":
		apiError(w, http.StatusForbidden, s.CallbackError)
		return
	}
	u := s.Users[s.SessionUser]
	if u == nil {
		apiError(w, http.StatusNotFound, "Errors.User.NotFound")
		return
	}
	s.handled = true
	oidcUser := u.OIDC
	if oidcUser.Subject == "" {
		oidcUser.Subject = u.ID
	}
	if oidcUser.Email == "" {
		oidcUser.Email, oidcUser.EmailVerified = u.Email, true
	}
	authURL, _ := url.Parse(s.authURL)
	q := s.OP.Authorize(testingT{}, s.authURL, oidcUser)
	writeJSON(w, map[string]any{"callbackUrl": appendQuery(authURL.Query().Get("redirect_uri"), q)})
}

// testingT lets the fake call oidctest's Authorize outside a test helper.
type testingT struct{ testing.TB }

func (testingT) Helper() {}
func (testingT) Fatalf(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		apiError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return false
	}
	return true
}

func apiError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": status, "message": message})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
