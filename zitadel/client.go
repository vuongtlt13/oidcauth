// Package zitadel calls the Zitadel v2 API (REST) the app needs to act as
// Zitadel's login UI for one external identity provider: the browser only
// sees that provider's page (e.g. Google), the app does the rest with a
// service user.
package zitadel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client calls the v2 API of one Zitadel instance as a service user.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
	// noRedirect is http without following redirects, for Authorize.
	noRedirect *http.Client
}

// New returns a client for the instance at baseURL (its issuer, e.g.
// https://id.viset.vn), authenticated with the personal access token of a
// service user. httpClient may be nil.
func New(baseURL, token string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	noRedirect := *httpClient
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		http:       httpClient,
		noRedirect: &noRedirect,
	}
}

// APIError is an error response of the API.
type APIError struct {
	Status int
	// Message is Zitadel's message, e.g.
	// "Errors.User.ProjectRequired (OIDC-foSyH49RvL)".
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("zitadel: %d %s", e.Status, e.Message)
}

// hasMessage tells whether err is an API error whose message contains key,
// e.g. "Errors.User.NotAllowedOrg".
func hasMessage(err error, key string) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && strings.Contains(apiErr.Message, key)
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("zitadel: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("zitadel: %s %s: %w", method, path, err)
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(raw))
		}
		return &APIError{Status: resp.StatusCode, Message: e.Message}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("zitadel: %s %s: decode response: %w", method, path, err)
	}
	return nil
}

// Authorize sends the authorization request authURL (built by the relying
// party) to Zitadel from the server and returns the ID of the auth request
// Zitadel created, read from the login UI redirect. When Zitadel answers
// without a login UI redirect (e.g. an error redirect to the client's
// redirect URI), it returns that location instead, for the browser to follow.
//
// This is how the app becomes the login UI of its own logins: with the
// instance feature "Login V2 required", Zitadel sends every auth request to
// the instance login UI, whatever base URI the application sets.
func (c *Client) Authorize(ctx context.Context, authURL string) (authRequestID, location string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := c.noRedirect.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("zitadel: authorize: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", "", &APIError{Status: resp.StatusCode, Message: "authorize: no redirect"}
	}
	loc, err := resp.Location()
	if err != nil {
		return "", "", fmt.Errorf("zitadel: authorize: %w", err)
	}
	if id := loc.Query().Get("authRequest"); id != "" {
		return id, "", nil
	}
	return "", loc.String(), nil
}

// StartIntent starts the login at identity provider idpID and returns the
// provider URL to send the browser to. The provider returns to Zitadel,
// which redirects to successURL with id, token (and user when the external
// account is linked), or to failureURL with error and error_description.
func (c *Client) StartIntent(ctx context.Context, idpID, successURL, failureURL string) (string, error) {
	in := map[string]any{
		"idpId": idpID,
		"urls":  map[string]string{"successUrl": successURL, "failureUrl": failureURL},
	}
	var out struct {
		AuthURL string `json:"authUrl"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/idp_intents", nil, in, &out); err != nil {
		return "", err
	}
	if out.AuthURL == "" {
		// Form POST (SAML) and LDAP intents need a page of their own.
		return "", errors.New("zitadel: identity provider does not use a redirect login")
	}
	return out.AuthURL, nil
}

// IDPLink is an external account linked to a Zitadel user.
type IDPLink struct {
	IDPID    string `json:"idpId"`
	UserID   string `json:"userId"`
	UserName string `json:"userName"`
}

// Intent is a succeeded identity provider login.
type Intent struct {
	IDPInformation IDPLink `json:"idpInformation"`
	// UserID is the Zitadel user the external account is linked to, if any.
	UserID string `json:"userId"`
	// CreateUser is the CreateUser request Zitadel prepared from the
	// external account, when it is not linked.
	CreateUser json.RawMessage `json:"createUser"`
}

// NewUser is what the app reads from Intent.CreateUser.
type NewUser struct {
	Username string `json:"username"`
	Human    struct {
		Profile struct {
			GivenName  string `json:"givenName"`
			FamilyName string `json:"familyName"`
		} `json:"profile"`
		Email struct {
			Email      string `json:"email"`
			IsVerified bool   `json:"isVerified"`
		} `json:"email"`
	} `json:"human"`
}

// NewUser decodes CreateUser; nil when absent.
func (i *Intent) NewUser() *NewUser {
	if len(i.CreateUser) == 0 {
		return nil
	}
	var u NewUser
	if json.Unmarshal(i.CreateUser, &u) != nil {
		return nil
	}
	return &u
}

// RetrieveIntent reads a succeeded intent, with the token from the success
// redirect.
func (c *Client) RetrieveIntent(ctx context.Context, intentID, intentToken string) (*Intent, error) {
	var out Intent
	err := c.do(ctx, http.MethodPost, "/v2/idp_intents/"+url.PathEscape(intentID), nil,
		map[string]string{"idpIntentToken": intentToken}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Auto-linking options of an identity provider.
const (
	AutoLinkingEmail    = "AUTO_LINKING_OPTION_EMAIL"
	AutoLinkingUsername = "AUTO_LINKING_OPTION_USERNAME"
)

// IDPOptions are the account options of an identity provider.
type IDPOptions struct {
	IsLinkingAllowed  bool   `json:"isLinkingAllowed"`
	IsCreationAllowed bool   `json:"isCreationAllowed"`
	IsAutoCreation    bool   `json:"isAutoCreation"`
	IsAutoUpdate      bool   `json:"isAutoUpdate"`
	AutoLinking       string `json:"autoLinking"`
}

// IDPOptions reads the account options of identity provider idpID.
func (c *Client) IDPOptions(ctx context.Context, idpID string) (*IDPOptions, error) {
	var out struct {
		IDP struct {
			Config struct {
				Options IDPOptions `json:"options"`
			} `json:"config"`
		} `json:"idp"`
	}
	if err := c.do(ctx, http.MethodGet, "/v2/idps/"+url.PathEscape(idpID), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out.IDP.Config.Options, nil
}

// User states that refuse a login.
const (
	UserStateInactive = "USER_STATE_INACTIVE"
	UserStateLocked   = "USER_STATE_LOCKED"
)

// User is a Zitadel user.
type User struct {
	UserID  string      `json:"userId"`
	State   string      `json:"state"`
	Details UserDetails `json:"details"`
}

// UserDetails are the object details of a user.
type UserDetails struct {
	// ResourceOwner is the organization of the user.
	ResourceOwner string `json:"resourceOwner"`
}

// UserQuery selects users: by email or username, within an organization
// when OrgID is set. Text matches ignore case.
type UserQuery struct {
	Email    string
	Username string
	OrgID    string
}

// ListUsers returns the users matching q.
func (c *Client) ListUsers(ctx context.Context, q UserQuery) ([]User, error) {
	const ignoreCase = "TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE"
	var queries []map[string]any
	if q.Email != "" {
		queries = append(queries, map[string]any{"emailQuery": map[string]string{"emailAddress": q.Email, "method": ignoreCase}})
	}
	if q.Username != "" {
		queries = append(queries, map[string]any{"userNameQuery": map[string]string{"userName": q.Username, "method": ignoreCase}})
	}
	if q.OrgID != "" {
		queries = append(queries, map[string]any{"organizationIdQuery": map[string]string{"organizationId": q.OrgID}})
	}
	var out struct {
		Result []User `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/users", nil, map[string]any{"queries": queries}, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// GetUser reads user userID.
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	var out struct {
		User User `json:"user"`
	}
	if err := c.do(ctx, http.MethodGet, "/v2/users/"+url.PathEscape(userID), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out.User, nil
}

// AddIDPLink links an external account to user userID.
func (c *Client) AddIDPLink(ctx context.Context, userID string, link IDPLink) error {
	return c.do(ctx, http.MethodPost, "/v2/users/"+url.PathEscape(userID)+"/links", nil,
		map[string]any{"idpLink": link}, nil)
}

// CreateUser creates a user in organization orgID from a CreateUser request
// prepared by Zitadel (Intent.CreateUser) and returns its ID.
func (c *Client) CreateUser(ctx context.Context, orgID string, request json.RawMessage) (string, error) {
	in := map[string]any{}
	if err := json.Unmarshal(request, &in); err != nil {
		return "", fmt.Errorf("zitadel: create user request: %w", err)
	}
	in["organizationId"] = orgID
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/users/new", nil, in, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// DefaultOrgID returns the default organization of the instance.
func (c *Client) DefaultOrgID(ctx context.Context) (string, error) {
	var out struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	in := map[string]any{"queries": []map[string]any{{"defaultQuery": map[string]any{}}}}
	if err := c.do(ctx, http.MethodPost, "/v2/organizations/_search", nil, in, &out); err != nil {
		return "", err
	}
	if len(out.Result) == 0 {
		return "", errors.New("zitadel: no default organization")
	}
	return out.Result[0].ID, nil
}

// LoginSettings are the login policy of an organization.
type LoginSettings struct {
	AllowExternalIDP  bool `json:"allowExternalIdp"`
	ForceMFA          bool `json:"forceMfa"`
	ForceMFALocalOnly bool `json:"forceMfaLocalOnly"`
}

// LoginSettings reads the login policy of organization orgID.
func (c *Client) LoginSettings(ctx context.Context, orgID string) (*LoginSettings, error) {
	var out struct {
		Settings LoginSettings `json:"settings"`
	}
	q := url.Values{"ctx.orgId": {orgID}}
	if err := c.do(ctx, http.MethodGet, "/v2/settings/login", q, nil, &out); err != nil {
		return nil, err
	}
	return &out.Settings, nil
}

// ActiveIDPs returns the IDs of the identity providers organization orgID
// offers at login (its own or the instance's); with linking, only those
// that allow linking existing users.
func (c *Client) ActiveIDPs(ctx context.Context, orgID string, linking bool) ([]string, error) {
	var out struct {
		IdentityProviders []struct {
			ID string `json:"id"`
		} `json:"identityProviders"`
	}
	q := url.Values{"ctx.orgId": {orgID}}
	if linking {
		q.Set("linkingAllowed", "true")
	}
	if err := c.do(ctx, http.MethodGet, "/v2/settings/login/idps", q, nil, &out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out.IdentityProviders))
	for _, p := range out.IdentityProviders {
		ids = append(ids, p.ID)
	}
	return ids, nil
}

// UserAgent describes the browser of a session, for the session list and
// audit.
type UserAgent struct {
	IP          string `json:"ip,omitempty"`
	Description string `json:"description,omitempty"`
}

// Session is a Zitadel session.
type Session struct {
	ID    string `json:"sessionId"`
	Token string `json:"sessionToken"`
}

// CreateSession creates a session of user userID checked by a succeeded
// intent (which it consumes).
func (c *Client) CreateSession(ctx context.Context, userID, intentID, intentToken string, ua *UserAgent) (*Session, error) {
	in := map[string]any{
		"checks": map[string]any{
			"user":      map[string]string{"userId": userID},
			"idpIntent": map[string]string{"idpIntentId": intentID, "idpIntentToken": intentToken},
		},
	}
	if ua != nil {
		in["userAgent"] = ua
	}
	var out Session
	if err := c.do(ctx, http.MethodPost, "/v2/sessions", nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AuthRequest is a pending OIDC auth request.
type AuthRequest struct {
	ID       string   `json:"id"`
	ClientID string   `json:"clientId"`
	Scope    []string `json:"scope"`
}

// orgScope restricts an auth request to the users of one organization.
const orgScope = "urn:zitadel:iam:org:id:"

// OrgID returns the organization the auth request is restricted to
// (urn:zitadel:iam:org:id:<id> scope), or "".
func (a *AuthRequest) OrgID() string {
	for _, s := range a.Scope {
		if id, ok := strings.CutPrefix(s, orgScope); ok {
			return id
		}
	}
	return ""
}

// AuthRequest reads auth request id.
func (c *Client) AuthRequest(ctx context.Context, id string) (*AuthRequest, error) {
	var out struct {
		AuthRequest AuthRequest `json:"authRequest"`
	}
	if err := c.do(ctx, http.MethodGet, "/v2/oidc/auth_requests/"+url.PathEscape(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out.AuthRequest, nil
}

// CreateCallback completes auth request id with session s and returns the
// client's redirect URI with the authorization code.
func (c *Client) CreateCallback(ctx context.Context, id string, s *Session) (string, error) {
	var out struct {
		CallbackURL string `json:"callbackUrl"`
	}
	in := map[string]any{"session": s}
	if err := c.do(ctx, http.MethodPost, "/v2/oidc/auth_requests/"+url.PathEscape(id), nil, in, &out); err != nil {
		return "", err
	}
	return out.CallbackURL, nil
}
