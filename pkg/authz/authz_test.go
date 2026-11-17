package authz

import (
	"net/http"
	"testing"
	"time"

	"github.com/snigdhasambitak/istio-key-auth/pkg/keys"
)

func authorizer() Authorizer {
	s := keys.NewStore()
	s.Set("default/orders", map[string]keys.Client{"k-orders": {Name: "orders-app", PathPrefixes: []string{"/v1/orders"}}})
	return Authorizer{Store: s, Config: DefaultConfig()}
}

func TestCheck(t *testing.T) {
	a := authorizer()
	cases := []struct {
		name    string
		headers map[string]string
		path    string
		status  int
		allowed bool
	}{
		{"no key", map[string]string{}, "/v1/orders", http.StatusUnauthorized, false},
		{"wrong key", map[string]string{"x-api-key": "nope"}, "/v1/orders", http.StatusUnauthorized, false},
		{"valid key", map[string]string{"x-api-key": "k-orders"}, "/v1/orders/7", 0, true},
		{"authorization scheme", map[string]string{"authorization": "ApiKey k-orders"}, "/v1/orders", 0, true},
		{"bearer is not an api key", map[string]string{"authorization": "Bearer k-orders"}, "/v1/orders", http.StatusUnauthorized, false},
		{"path not allowed", map[string]string{"x-api-key": "k-orders"}, "/v1/users", http.StatusForbidden, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := a.Check(Request{Method: "GET", Host: "api.example.com", Path: tc.path, Headers: tc.headers})
			if d.Allowed != tc.allowed || d.Status != tc.status {
				t.Fatalf("got allowed=%v status=%d (%s), want allowed=%v status=%d", d.Allowed, d.Status, d.Reason, tc.allowed, tc.status)
			}
		})
	}
}

func TestAllowedRequestsNameTheClientAndDropTheKey(t *testing.T) {
	d := authorizer().Check(Request{Method: "GET", Host: "api.example.com", Path: "/v1/orders", Headers: map[string]string{"x-api-key": "k-orders"}})
	if d.SetHeaders["x-api-client"] != "orders-app" {
		t.Fatalf("client header = %q", d.SetHeaders["x-api-client"])
	}
	if len(d.RemoveHeaders) != 1 || d.RemoveHeaders[0] != "x-api-key" {
		t.Fatalf("remove headers = %v", d.RemoveHeaders)
	}
}

func TestExpiredKeysMethodsGroupsAndQueryKeys(t *testing.T) {
	s := keys.NewStore()
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	s.Set("x", map[string]keys.Client{
		"k-reader":  {Name: "reader", Methods: []string{"GET"}, Groups: []string{"read-only", "partners"}},
		"k-expires": {Name: "temp", ExpiresAt: expiry},
	})
	cfg := DefaultConfig()
	cfg.QueryParam = "api_key"
	a := Authorizer{Store: s, Config: cfg, Now: func() time.Time { return expiry }}
	req := func(method, path string, headers map[string]string) Decision {
		return a.Check(Request{Method: method, Host: "h", Path: path, Headers: headers})
	}

	if d := req("GET", "/", map[string]string{"x-api-key": "k-expires"}); d.Status != http.StatusUnauthorized || d.Reason != "expired api key" {
		t.Fatalf("expired key: %+v", d)
	}
	if d := req("POST", "/", map[string]string{"x-api-key": "k-reader"}); d.Status != http.StatusForbidden {
		t.Fatalf("method not allowed: %+v", d)
	}
	d := req("GET", "/hook?api_key=k-reader&x=1", map[string]string{})
	if !d.Allowed || d.SetHeaders["x-api-client-groups"] != "read-only,partners" {
		t.Fatalf("query key with groups: %+v", d)
	}
	if len(d.RemoveQueryParams) != 1 || d.RemoveQueryParams[0] != "api_key" || len(d.RemoveHeaders) != 0 {
		t.Fatalf("query key is not stripped: %+v", d)
	}
	a.Config.QueryParam = ""
	if d := req("GET", "/hook?api_key=k-reader", map[string]string{}); d.Allowed {
		t.Fatal("query keys are accepted although disabled")
	}
}
