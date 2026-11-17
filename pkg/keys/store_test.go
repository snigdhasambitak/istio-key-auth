package keys

import (
	"testing"
	"time"
)

func TestLookupFindsTheOwner(t *testing.T) {
	s := NewStore()
	s.Set("default/team-a", map[string]Client{"secret-a": {Name: "team-a"}})
	s.Set("default/team-b", map[string]Client{"secret-b": {Name: "team-b"}})

	if c, ok := s.Lookup("secret-b"); !ok || c.Name != "team-b" {
		t.Fatalf("got %v %v, want team-b", c, ok)
	}
	if _, ok := s.Lookup("wrong"); ok {
		t.Fatal("an unknown key was accepted")
	}
	if _, ok := s.Lookup(""); ok {
		t.Fatal("an empty key was accepted")
	}
}

func TestReplacingAndDeletingASource(t *testing.T) {
	s := NewStore()
	s.Set("default/team-a", map[string]Client{"old": {Name: "team-a"}})
	s.Set("default/team-a", map[string]Client{"new": {Name: "team-a"}})
	if _, ok := s.Lookup("old"); ok {
		t.Fatal("a rotated key still works")
	}
	if _, ok := s.Lookup("new"); !ok {
		t.Fatal("the new key does not work")
	}
	s.Delete("default/team-a")
	if s.Len() != 0 {
		t.Fatalf("store has %d keys after delete", s.Len())
	}
}

func TestAllows(t *testing.T) {
	c := Client{Hosts: []string{"api.example.com", "*.internal.example.com"}, PathPrefixes: []string{"/v1/orders"}}
	cases := []struct {
		host, path string
		want       bool
	}{
		{"api.example.com", "/v1/orders/42", true},
		{"API.example.com:443", "/v1/orders?x=1", true},
		{"billing.internal.example.com", "/v1/orders", true},
		{"other.example.com", "/v1/orders", false},
		{"api.example.com", "/v1/users", false},
	}
	for _, tc := range cases {
		if got := c.Allows("GET", tc.host, tc.path); got != tc.want {
			t.Errorf("Allows(%q, %q) = %v, want %v", tc.host, tc.path, got, tc.want)
		}
	}
	if !(Client{}).Allows("DELETE", "anything", "/anything") {
		t.Error("a client without limits should be allowed everywhere")
	}
}

func TestMethodsAndExpiry(t *testing.T) {
	c := Client{Methods: []string{"GET", "head"}, ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	if !c.Allows("HEAD", "h", "/") || c.Allows("POST", "h", "/") {
		t.Error("methods are not matched case-insensitively or not enforced")
	}
	if c.Expired(time.Date(2029, 12, 31, 0, 0, 0, 0, time.UTC)) || !c.Expired(c.ExpiresAt) {
		t.Error("expiry is not enforced at its exact time")
	}
	if (Client{}).Expired(time.Now()) {
		t.Error("a key without expiry expired")
	}
}
