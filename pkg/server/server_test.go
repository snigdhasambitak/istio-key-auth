package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	"github.com/snigdhasambitak/istio-key-auth/pkg/authz"
	"github.com/snigdhasambitak/istio-key-auth/pkg/keys"
)

func testAuthorizer() authz.Authorizer {
	s := keys.NewStore()
	s.Set("default/orders", map[string]keys.Client{"k-orders": {Name: "orders-app"}})
	return authz.Authorizer{Store: s, Config: authz.DefaultConfig()}
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func checkRequest(headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
		Http: &authv3.AttributeContext_HttpRequest{Host: "api.example.com", Path: "/v1/orders", Headers: headers},
	}}}
}

func TestGRPCAllowsAValidKey(t *testing.T) {
	g := &GRPC{Authorizer: testAuthorizer(), Log: quiet}
	resp, err := g.Check(context.Background(), checkRequest(map[string]string{"x-api-key": "k-orders"}))
	if err != nil || resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("got %v, %v", resp.GetStatus(), err)
	}
	ok := resp.GetOkResponse()
	if len(ok.GetHeaders()) != 1 || ok.GetHeaders()[0].GetHeader().GetValue() != "orders-app" {
		t.Fatalf("headers = %v", ok.GetHeaders())
	}
	if len(ok.GetHeadersToRemove()) != 1 || ok.GetHeadersToRemove()[0] != "x-api-key" {
		t.Fatalf("headers to remove = %v", ok.GetHeadersToRemove())
	}
}

func TestGRPCDeniesWithA401(t *testing.T) {
	g := &GRPC{Authorizer: testAuthorizer(), Log: quiet}
	resp, _ := g.Check(context.Background(), checkRequest(map[string]string{"x-api-key": "wrong"}))
	if resp.GetStatus().GetCode() != int32(codes.Unauthenticated) || resp.GetDeniedResponse().GetStatus().GetCode() != 401 {
		t.Fatalf("got %v", resp)
	}
}

func TestHTTPCheck(t *testing.T) {
	h := &HTTP{Authorizer: testAuthorizer(), Log: quiet, PathPrefix: "/check"}
	for key, want := range map[string]int{"k-orders": http.StatusOK, "wrong": http.StatusUnauthorized} {
		req := httptest.NewRequest(http.MethodGet, "/check/v1/orders", nil)
		req.Header.Set("X-Api-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("key %q: status %d, want %d", key, rec.Code, want)
		}
		if want == http.StatusOK && rec.Header().Get("x-api-client") != "orders-app" {
			t.Errorf("client header = %q", rec.Header().Get("x-api-client"))
		}
	}
}
