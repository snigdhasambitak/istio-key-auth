package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/snigdhasambitak/istio-key-auth/pkg/authz"
)

var decisions = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "istio_key_auth_decisions_total",
	Help: "Authorization decisions by transport, result and client.",
}, []string{"transport", "result", "client"})

func record(d authz.Decision, transport string) {
	result := "allowed"
	if !d.Allowed {
		result = map[int]string{401: "unauthenticated", 403: "forbidden"}[d.Status]
	}
	decisions.WithLabelValues(transport, result, d.Client).Inc()
}

// HTTP is the check endpoint for Istio's envoyExtAuthzHttp provider. Envoy forwards the original request's path and
// headers; a 200 lets it through, anything else is returned to the caller.
type HTTP struct {
	Authorizer authz.Authorizer
	Log        *slog.Logger
	// PathPrefix is configured as pathPrefix on the provider and removed before the path is checked.
	PathPrefix string
}

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	headers := make(map[string]string, len(r.Header))
	for name, values := range r.Header {
		headers[strings.ToLower(name)] = strings.Join(values, ",")
	}
	path := strings.TrimPrefix(r.URL.RequestURI(), h.PathPrefix)
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	d := h.Authorizer.Check(authz.Request{Method: r.Method, Host: r.Host, Path: path, Headers: headers})
	record(d, "http")
	if !d.Allowed {
		h.Log.Info("denied", "host", r.Host, "path", path, "status", d.Status, "reason", d.Reason, "client", d.Client)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(d.Status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": d.Reason})
		return
	}
	for name, value := range d.SetHeaders {
		w.Header().Set(name, value)
	}
	w.WriteHeader(http.StatusOK)
}

// Ops serves /healthz, /readyz and /metrics. Ready turns true once the first keys have loaded.
func Ops(ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}
