// Package keys holds the API keys the authorizer accepts. Only SHA-256 hashes of the keys are kept in memory.
package keys

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"
	"sync"
	"time"
)

// Client is who an API key belongs to and what it may reach.
type Client struct {
	// Name is sent to the upstream so it knows which client called.
	Name string
	// Hosts the key may call. Empty means any host.
	Hosts []string
	// PathPrefixes the key may call. Empty means any path.
	PathPrefixes []string
	// Methods the key may use, for example GET and HEAD for a read-only key. Empty means any method.
	Methods []string
	// Groups are passed to the upstream, so the application or an Istio policy can act on them.
	Groups []string
	// ExpiresAt is when the key stops working. Zero means it never expires.
	ExpiresAt time.Time
}

// Allows reports whether the client may call host and path with method.
func (c Client) Allows(method, host, path string) bool {
	return matchHost(c.Hosts, host) && matchPrefix(c.PathPrefixes, path) && matchMethod(c.Methods, method)
}

// Expired reports whether the key has passed its expiry at now.
func (c Client) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)
}

func matchMethod(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

func matchHost(hosts []string, host string) bool {
	if len(hosts) == 0 {
		return true
	}
	host = strings.ToLower(stripPort(host))
	for _, h := range hosts {
		h = strings.ToLower(h)
		if h == host || (strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])) {
			return true
		}
	}
	return false
}

func matchPrefix(prefixes []string, path string) bool {
	if len(prefixes) == 0 {
		return true
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		return host[:i]
	}
	return host
}

type entry struct {
	hash   [sha256.Size]byte
	client Client
}

// Store is a concurrency-safe set of API keys, grouped by the source that supplied them (for example a Secret), so
// one source can be replaced or removed without touching the others.
type Store struct {
	mu      sync.RWMutex
	sources map[string][]entry
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{sources: map[string][]entry{}}
}

// Set replaces every key that came from source.
func (s *Store) Set(source string, keys map[string]Client) {
	entries := make([]entry, 0, len(keys))
	for key, client := range keys {
		if key == "" {
			continue
		}
		entries = append(entries, entry{hash: sha256.Sum256([]byte(key)), client: client})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(entries) == 0 {
		delete(s.sources, source)
		return
	}
	s.sources[source] = entries
}

// Delete removes every key that came from source.
func (s *Store) Delete(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sources, source)
}

// Len is the number of keys in the store.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, e := range s.sources {
		n += len(e)
	}
	return n
}

// Lookup returns the client that owns key. Every stored hash is compared in constant time, so the time taken does
// not reveal how close a guess was.
func (s *Store) Lookup(key string) (Client, bool) {
	if key == "" {
		return Client{}, false
	}
	sum := sha256.Sum256([]byte(key))
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found Client
	ok := false
	for _, entries := range s.sources {
		for _, e := range entries {
			if subtle.ConstantTimeCompare(sum[:], e.hash[:]) == 1 {
				found, ok = e.client, true
			}
		}
	}
	return found, ok
}
