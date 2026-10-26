package zitadel

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// Errors of IDPLogin.Finish. Zitadel API errors are returned as *APIError.
var (
	// ErrNotLinked: the external account is linked to no Zitadel user, and
	// the identity provider neither auto-links nor auto-creates one.
	ErrNotLinked = errors.New("zitadel: external account is not linked to a user")
	// ErrNotAllowed: the user is outside the organization the app requires,
	// or that organization does not allow this identity provider.
	ErrNotAllowed = errors.New("zitadel: user is not allowed to log in with this identity provider")
	// ErrAccessDenied: the user has no grant for the application's project.
	ErrAccessDenied = errors.New("zitadel: user has no access to the application")
	// ErrUserInactive: the Zitadel user is deactivated or locked.
	ErrUserInactive = errors.New("zitadel: user is not active")
	// ErrMFARequired: the user's organization requires a second factor for
	// external logins, which this login cannot ask for.
	ErrMFARequired = errors.New("zitadel: organization requires multi-factor authentication")
	// ErrAuthRequestExpired: the OIDC auth request is unknown, expired or
	// already completed.
	ErrAuthRequestExpired = errors.New("zitadel: auth request expired or already handled")
	// ErrIntentFailed: the login at the identity provider was cancelled or
	// failed (Zitadel returned to the failure URL).
	ErrIntentFailed = errors.New("zitadel: login at the identity provider failed")
)

// IsUserError reports whether err is a refusal or a failure on the user's
// side (the errors above, or a Zitadel API error 4xx such as an expired
// intent) rather than Zitadel being unreachable, misconfigured or failing.
func IsUserError(err error) bool {
	for _, target := range []error{ErrNotLinked, ErrNotAllowed, ErrAccessDenied,
		ErrUserInactive, ErrMFARequired, ErrAuthRequestExpired, ErrIntentFailed} {
		if errors.Is(err, target) {
			return true
		}
	}
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500
}

// IDPLogin logs users in to Zitadel with one external identity provider
// (e.g. Google) without Zitadel's login UI, the way the login UI itself does
// it: start an intent at the provider, then turn the succeeded intent into a
// session and complete the OIDC auth request with it. The app then exchanges
// the code as for any other login, so the result is a regular Zitadel login
// (Zitadel user, roles, back-channel logout).
//
// The service user behind the client needs the instance role
// IAM_LOGIN_CLIENT.
type IDPLogin struct {
	api   *Client
	idpID string
}

// NewIDPLogin returns the login with identity provider idpID.
func NewIDPLogin(api *Client, idpID string) *IDPLogin {
	return &IDPLogin{api: api, idpID: idpID}
}

// IDPID is the identity provider of the login.
func (l *IDPLogin) IDPID() string { return l.idpID }

// Authorize sends the authorization request authURL to Zitadel. It returns
// the auth request ID, to pass to Finish, or, when Zitadel rejected the
// request, the client's redirect URI with the error, for the browser.
func (l *IDPLogin) Authorize(ctx context.Context, authURL string) (authRequestID, errorRedirect string, err error) {
	return l.api.Authorize(ctx, authURL)
}

// StartIntent starts the login at the identity provider and returns the URL
// to send the browser to. Zitadel returns to successURL with the intent (id,
// token) or to failureURL with error and error_description.
func (l *IDPLogin) StartIntent(ctx context.Context, successURL, failureURL string) (string, error) {
	return l.api.StartIntent(ctx, l.idpID, successURL, failureURL)
}

// Finish completes auth request authRequestID with the intent of the
// success redirect (query id and token) and returns the client's redirect
// URI with the authorization code.
//
// The Zitadel user is the one the external account is linked to. Otherwise,
// following the identity provider options: auto-linking by verified email
// (or username) links the single matching user, if their organization
// allows the provider; auto-creation creates a user in the organization the
// auth request is restricted to (urn:zitadel:iam:org:id scope), or in the
// default organization.
func (l *IDPLogin) Finish(ctx context.Context, authRequestID, intentID, intentToken string, ua *UserAgent) (string, error) {
	authReq, err := l.api.AuthRequest(ctx, authRequestID)
	if err != nil {
		return "", authRequestError(err)
	}
	intent, err := l.api.RetrieveIntent(ctx, intentID, intentToken)
	if err != nil {
		return "", err
	}
	if intent.IDPInformation.IDPID != l.idpID {
		return "", fmt.Errorf("zitadel: intent of identity provider %q, want %q", intent.IDPInformation.IDPID, l.idpID)
	}
	orgID := authReq.OrgID()

	user, err := l.resolveUser(ctx, intent, orgID)
	if err != nil {
		return "", err
	}
	if user.State == UserStateInactive || user.State == UserStateLocked {
		return "", fmt.Errorf("%w: user %s is %s", ErrUserInactive, user.UserID, user.State)
	}
	if orgID != "" && user.Details.ResourceOwner != orgID {
		return "", fmt.Errorf("%w: user %s belongs to org %s, the auth request requires org %s",
			ErrNotAllowed, user.UserID, user.Details.ResourceOwner, orgID)
	}
	settings, err := l.api.LoginSettings(ctx, user.Details.ResourceOwner)
	if err != nil {
		return "", err
	}
	if settings.ForceMFA && !settings.ForceMFALocalOnly {
		return "", fmt.Errorf("%w: org %s of user %s", ErrMFARequired, user.Details.ResourceOwner, user.UserID)
	}

	session, err := l.api.CreateSession(ctx, user.UserID, intentID, intentToken, ua)
	if err != nil {
		return "", err
	}
	callback, err := l.api.CreateCallback(ctx, authRequestID, session)
	if err != nil {
		switch {
		case hasMessage(err, "Errors.User.ProjectRequired"), hasMessage(err, "Errors.User.GrantRequired"):
			return "", fmt.Errorf("%w: user %s: %w", ErrAccessDenied, user.UserID, err)
		case hasMessage(err, "Errors.User.NotAllowedOrg"):
			return "", fmt.Errorf("%w: user %s: %w", ErrNotAllowed, user.UserID, err)
		}
		return "", authRequestError(err)
	}
	return callback, nil
}

// resolveUser returns the Zitadel user of the external account, linking or
// creating it as the identity provider options allow.
func (l *IDPLogin) resolveUser(ctx context.Context, intent *Intent, orgID string) (*User, error) {
	if intent.UserID != "" {
		return l.api.GetUser(ctx, intent.UserID)
	}
	opts, err := l.api.IDPOptions(ctx, l.idpID)
	if err != nil {
		return nil, err
	}
	newUser := intent.NewUser()
	reason := "the identity provider neither auto-links nor auto-creates users"

	var query *UserQuery
	switch {
	case opts.AutoLinking == AutoLinkingEmail && newUser != nil && newUser.Human.Email.IsVerified && newUser.Human.Email.Email != "":
		query = &UserQuery{Email: newUser.Human.Email.Email, OrgID: orgID}
	case opts.AutoLinking == AutoLinkingUsername && intent.IDPInformation.UserName != "":
		query = &UserQuery{Username: intent.IDPInformation.UserName, OrgID: orgID}
	}
	if query != nil {
		users, err := l.api.ListUsers(ctx, *query)
		if err != nil {
			return nil, err
		}
		// Several matches (the same email in two organizations): linking
		// would be a guess, so the user links from an existing session.
		switch len(users) {
		case 0:
			reason = fmt.Sprintf("auto-linking by %s found no user", opts.AutoLinking)
		case 1:
			user := &users[0]
			if err := l.checkLinkingAllowed(ctx, user.Details.ResourceOwner); err != nil {
				return nil, err
			}
			if err := l.api.AddIDPLink(ctx, user.UserID, intent.IDPInformation); err != nil {
				return nil, err
			}
			return user, nil
		default:
			ids := make([]string, len(users))
			for i, u := range users {
				ids[i] = u.UserID + "@org:" + u.Details.ResourceOwner
			}
			reason = fmt.Sprintf("auto-linking by %s matches %d users %v", opts.AutoLinking, len(users), ids)
		}
	}

	if opts.IsAutoCreation && newUser != nil {
		// CreateUser requires both names; the login UI asks for missing ones.
		if newUser.Human.Profile.GivenName == "" || newUser.Human.Profile.FamilyName == "" {
			return nil, fmt.Errorf("%w: %s, auto-creation needs given and family name", ErrNotLinked, reason)
		}
		if orgID == "" {
			if orgID, err = l.api.DefaultOrgID(ctx); err != nil {
				return nil, err
			}
		}
		id, err := l.api.CreateUser(ctx, orgID, intent.CreateUser)
		if err != nil {
			return nil, err
		}
		return &User{UserID: id, Details: UserDetails{ResourceOwner: orgID}}, nil
	}
	return nil, fmt.Errorf("%w: idp %s: %s", ErrNotLinked, l.idpID, reason)
}

// checkLinkingAllowed tells whether organization orgID offers the identity
// provider for linking existing users.
func (l *IDPLogin) checkLinkingAllowed(ctx context.Context, orgID string) error {
	settings, err := l.api.LoginSettings(ctx, orgID)
	if err != nil {
		return err
	}
	if !settings.AllowExternalIDP {
		return fmt.Errorf("%w: org %s does not allow external identity providers", ErrNotAllowed, orgID)
	}
	ids, err := l.api.ActiveIDPs(ctx, orgID, true)
	if err != nil {
		return err
	}
	if !slices.Contains(ids, l.idpID) {
		return fmt.Errorf("%w: org %s does not offer identity provider %s for linking (it offers %v)",
			ErrNotAllowed, orgID, l.idpID, ids)
	}
	return nil
}

func authRequestError(err error) error {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == 404 || hasMessage(err, "Errors.AuthRequest.AlreadyHandled") {
		return fmt.Errorf("%w: %w", ErrAuthRequestExpired, err)
	}
	return err
}
