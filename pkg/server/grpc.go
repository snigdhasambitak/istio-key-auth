// Package server exposes the authorizer to Envoy: the gRPC ext_authz v3 API (Istio's envoyExtAuthzGrpc provider), an
// HTTP check endpoint (envoyExtAuthzHttp), health checks and Prometheus metrics.
package server

import (
	"context"
	"encoding/json"
	"log/slog"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/snigdhasambitak/istio-key-auth/pkg/authz"
)

// GRPC implements envoy.service.auth.v3.Authorization.
type GRPC struct {
	authv3.UnimplementedAuthorizationServer
	Authorizer authz.Authorizer
	Log        *slog.Logger
}

// Check answers one ext_authz request.
func (g *GRPC) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	http := req.GetAttributes().GetRequest().GetHttp()
	d := g.Authorizer.Check(authz.Request{Method: http.GetMethod(), Host: http.GetHost(), Path: http.GetPath(), Headers: http.GetHeaders()})
	record(d, "grpc")
	if !d.Allowed {
		g.Log.Info("denied", "host", http.GetHost(), "path", http.GetPath(), "status", d.Status, "reason", d.Reason, "client", d.Client)
		return denied(d), nil
	}
	ok := &authv3.OkHttpResponse{HeadersToRemove: d.RemoveHeaders, QueryParametersToRemove: d.RemoveQueryParams}
	for name, value := range d.SetHeaders {
		ok.Headers = append(ok.Headers, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: name, Value: value},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return &authv3.CheckResponse{
		Status:       &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: ok},
	}, nil
}

func denied(d authz.Decision) *authv3.CheckResponse {
	body, _ := json.Marshal(map[string]string{"error": d.Reason})
	code := codes.Unauthenticated
	if d.Status == 403 {
		code = codes.PermissionDenied
	}
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(code)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
			Status: &typev3.HttpStatus{Code: typev3.StatusCode(d.Status)},
			Body:   string(body),
			Headers: []*corev3.HeaderValueOption{{
				Header: &corev3.HeaderValue{Key: "content-type", Value: "application/json"},
			}},
		}},
	}
}
