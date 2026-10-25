package oidcauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SafeReturnTo accepts only same-origin relative paths ("/jobs?x=1") and
// returns fallback for anything else (absolute URLs, scheme-relative "//host",
// backslash tricks, control characters), preventing open redirects.
func SafeReturnTo(raw, fallback string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") ||
		strings.Contains(raw, `\`) {
		return fallback
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return fallback
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return fallback
	}
	return raw
}

// ErrTicketNotFound is returned when a ticket is unknown, expired or used.
var ErrTicketNotFound = errors.New("oidcauth: ticket not found or expired")

// TicketStore hands a value (typically the session token the app issued after
// a successful login) from the callback redirect to the SPA without putting
// the token itself in a URL. A ticket is random, short-lived and single-use.
//
// Implementations must make Take atomic (get + delete). Use MemoryTicketStore
// for a single instance; back it with Redis (GETDEL) when running replicas.
type TicketStore interface {
	Put(ctx context.Context, value string, ttl time.Duration) (ticket string, err error)
	Take(ctx context.Context, ticket string) (value string, err error)
}

// MemoryTicketStore is an in-process TicketStore.
type MemoryTicketStore struct {
	mu    sync.Mutex
	items map[string]memoryTicket
	now   func() time.Time
}

type memoryTicket struct {
	value     string
	expiresAt time.Time
}

// NewMemoryTicketStore returns an empty in-process store.
func NewMemoryTicketStore() *MemoryTicketStore {
	return &MemoryTicketStore{items: map[string]memoryTicket{}, now: time.Now}
}

func (s *MemoryTicketStore) Put(_ context.Context, value string, ttl time.Duration) (string, error) {
	ticket := randomToken()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.items {
		if now.After(v.expiresAt) {
			delete(s.items, k)
		}
	}
	s.items[ticket] = memoryTicket{value: value, expiresAt: now.Add(ttl)}
	return ticket, nil
}

func (s *MemoryTicketStore) Take(_ context.Context, ticket string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[ticket]
	if !ok {
		return "", ErrTicketNotFound
	}
	delete(s.items, ticket)
	if s.now().After(item.expiresAt) {
		return "", ErrTicketNotFound
	}
	return item.value, nil
}
