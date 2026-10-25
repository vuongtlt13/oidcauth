package oidcauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// flow is the per-login state kept in the browser between Start and Finish.
// It is sealed with AES-256-GCM (confidential + tamper-proof) and bound to the
// state value as additional data, so a cookie cannot be replayed for another
// state.
type flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	ReturnTo string `json:"r,omitempty"`
	// Scope is the space-separated scope sent, the fallback for the granted
	// scope when the token response omits it (RFC 6749, section 5.1).
	Scope string `json:"sc,omitempty"`
	// IssuedAt is when the login started; max_age is measured from it.
	IssuedAt int64 `json:"i"`
	// MaxAge is the max_age sent, in seconds; auth_time is then required.
	MaxAge *int64 `json:"m,omitempty"`
	// ACR lists acr_values the ID token acr must match (Config.RequireACR).
	ACR       []string `json:"a,omitempty"`
	ExpiresAt int64    `json:"e"`
}

type flowCodec struct {
	aead     cipher.AEAD
	prefix   string
	path     string
	insecure bool
	ttl      time.Duration
	now      func() time.Time
}

func newFlowCodec(cfg Config) *flowCodec {
	key := sha256.Sum256([]byte("oidcauth/flow/v1\x00" + cfg.CookieSecret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // 32-byte key: cannot fail
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &flowCodec{
		aead:     aead,
		prefix:   cfg.CookieName,
		path:     cfg.CookiePath,
		insecure: cfg.CookieInsecure,
		ttl:      cfg.FlowTTL,
		now:      time.Now,
	}
}

// name derives a per-state cookie name so parallel logins in several tabs do
// not overwrite each other.
func (c *flowCodec) name(state string) string {
	sum := sha256.Sum256([]byte(state))
	return c.prefix + "_" + hex.EncodeToString(sum[:6])
}

// encode seals f. crossSitePost marks a form_post login: the provider POSTs
// the callback cross-site, which a SameSite=Lax cookie does not survive.
func (c *flowCodec) encode(f flow, crossSitePost bool) (*http.Cookie, error) {
	f.ExpiresAt = c.now().Add(c.ttl).Unix()
	plain, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: encode flow: %w", err)
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("oidcauth: random: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, plain, []byte(f.State))
	ck := c.cookie(c.name(f.State), base64.RawURLEncoding.EncodeToString(sealed), int(c.ttl.Seconds()))
	if crossSitePost {
		ck.SameSite = http.SameSiteNoneMode
		ck.Secure = true // browsers drop SameSite=None cookies without Secure
	}
	return ck, nil
}

func (c *flowCodec) decode(state, value string) (*flow, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(sealed) < c.aead.NonceSize() {
		return nil, ErrInvalidState
	}
	nonce, body := sealed[:c.aead.NonceSize()], sealed[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, body, []byte(state))
	if err != nil {
		return nil, ErrInvalidState
	}
	var f flow
	if err := json.Unmarshal(plain, &f); err != nil {
		return nil, ErrInvalidState
	}
	if subtle.ConstantTimeCompare([]byte(f.State), []byte(state)) != 1 {
		return nil, ErrInvalidState
	}
	if c.now().Unix() > f.ExpiresAt {
		return nil, ErrInvalidState
	}
	return &f, nil
}

func (c *flowCodec) clear(state string) *http.Cookie {
	ck := c.cookie(c.name(state), "", -1)
	ck.Expires = time.Unix(0, 0)
	return ck
}

// cookie is HttpOnly and SameSite=Lax: Lax (not Strict) is required because
// the callback is a top-level cross-site navigation from the provider back to
// the app.
func (c *flowCodec) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     c.path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !c.insecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(fmt.Errorf("oidcauth: random: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
