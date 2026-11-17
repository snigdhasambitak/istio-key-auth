// Package authz decides whether a request carries an API key that may call the requested host and path. It knows
// nothing about Envoy or HTTP; the server package adapts it to both.
package authz

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/snigdhasambitak/istio-key-auth/pkg/keys"
)

// Config says where the key is read from and what is passed upstream.
type Config struct {
	// KeyHeader carries the key, for example x-api-key.
	KeyHeader string
	// AuthorizationScheme also accepts "Authorization: <scheme> <key>" when set, for example ApiKey.
	AuthorizationScheme string
	// QueryParam also accepts the key as this query parameter when set. Keys in URLs end up in access logs, so it
	// is off by default and meant for callers such as webhook senders that cannot set headers.
	QueryParam string
	// ClientHeader is added to the upstream request with the client's name.
	ClientHeader string
	// GroupsHeader is added to the upstream request with the client's groups, comma separated, when it has any.
	GroupsHeader string
	// StripKey removes the key from the request before it reaches the upstream.
	StripKey bool
}

// DefaultConfig is what the server uses unless flags say otherwise.
func DefaultConfig() Config {
	return Config{KeyHeader: "x-api-key", AuthorizationScheme: "ApiKey", ClientHeader: "x-api-client",
		GroupsHeader: "x-api-client-groups", StripKey: true}
}

// Request is the part of an HTTP request the decision depends on. Header names must be lower case, as Envoy sends
// them; Path includes the query string.
type Request struct {
	Method  string
	Host    string
	Path    string
	Headers map[string]string
}

// Decision is the outcome of one check.
type Decision struct {
	Allowed bool
	// Status is the HTTP status for a denied request: 401 without a valid key, 403 when the key may not call here.
	Status int
	Reason string
	Client string
	// SetHeaders are added to the upstream request; RemoveHeaders and RemoveQueryParams are taken off it.
	SetHeaders        map[string]string
	RemoveHeaders     []string
	RemoveQueryParams []string
}

// Authorizer checks requests against a key store.
type Authorizer struct {
	Store  *keys.Store
	Config Config
	// Now is the clock used for key expiry; nil means time.Now.
	Now func() time.Time
}

// Check decides a request.
func (a Authorizer) Check(r Request) Decision {
	key, header, param := a.key(r)
	if key == "" {
		return Decision{Status: http.StatusUnauthorized, Reason: "missing api key"}
	}
	client, ok := a.Store.Lookup(key)
	if !ok {
		return Decision{Status: http.StatusUnauthorized, Reason: "invalid api key"}
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if client.Expired(now()) {
		return Decision{Status: http.StatusUnauthorized, Reason: "expired api key", Client: client.Name}
	}
	if !client.Allows(r.Method, r.Host, r.Path) {
		return Decision{Status: http.StatusForbidden, Reason: "api key may not call this host, path or method", Client: client.Name}
	}
	d := Decision{Allowed: true, Client: client.Name, SetHeaders: map[string]string{}}
	if a.Config.ClientHeader != "" {
		d.SetHeaders[strings.ToLower(a.Config.ClientHeader)] = client.Name
	}
	if a.Config.GroupsHeader != "" && len(client.Groups) > 0 {
		d.SetHeaders[strings.ToLower(a.Config.GroupsHeader)] = strings.Join(client.Groups, ",")
	}
	if a.Config.StripKey {
		if header != "" {
			d.RemoveHeaders = []string{header}
		}
		if param != "" {
			d.RemoveQueryParams = []string{param}
		}
	}
	return d
}

// key returns the presented key and the header or query parameter it came from.
func (a Authorizer) key(r Request) (key, header, param string) {
	if h := strings.ToLower(a.Config.KeyHeader); h != "" {
		if v := strings.TrimSpace(r.Headers[h]); v != "" {
			return v, h, ""
		}
	}
	if scheme := a.Config.AuthorizationScheme; scheme != "" {
		v := strings.TrimSpace(r.Headers["authorization"])
		if len(v) > len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) && v[len(scheme)] == ' ' {
			return strings.TrimSpace(v[len(scheme)+1:]), "authorization", ""
		}
	}
	if p := a.Config.QueryParam; p != "" {
		if i := strings.IndexByte(r.Path, '?'); i >= 0 {
			if q, err := url.ParseQuery(r.Path[i+1:]); err == nil {
				if v := strings.TrimSpace(q.Get(p)); v != "" {
					return v, "", p
				}
			}
		}
	}
	return "", "", ""
}
