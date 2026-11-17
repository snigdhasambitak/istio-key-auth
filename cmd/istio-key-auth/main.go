// Command istio-key-auth is an external authorizer for Istio that accepts requests carrying a known API key.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/snigdhasambitak/istio-key-auth/pkg/authz"
	"github.com/snigdhasambitak/istio-key-auth/pkg/keys"
	"github.com/snigdhasambitak/istio-key-auth/pkg/server"
)

var version = "dev"

func main() {
	cfg := authz.DefaultConfig()
	grpcAddr := flag.String("grpc-addr", ":9001", "ext_authz gRPC listen address")
	httpAddr := flag.String("http-addr", ":8000", "ext_authz HTTP listen address")
	opsAddr := flag.String("ops-addr", ":9090", "health and metrics listen address")
	httpPrefix := flag.String("http-path-prefix", "", "pathPrefix configured on Istio's envoyExtAuthzHttp provider")
	namespace := flag.String("namespace", "", "namespace to read API key Secrets from (empty: every namespace)")
	keysFile := flag.String("keys-file", "", "read keys from this file instead of Kubernetes Secrets")
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig outside the cluster (default: in-cluster config)")
	flag.StringVar(&cfg.KeyHeader, "key-header", cfg.KeyHeader, "header that carries the API key")
	flag.StringVar(&cfg.AuthorizationScheme, "authorization-scheme", cfg.AuthorizationScheme,
		`also accept "Authorization: <scheme> <key>" (empty to disable)`)
	flag.StringVar(&cfg.QueryParam, "key-query-param", cfg.QueryParam,
		"also accept the key as this query parameter (empty to disable; keys in URLs reach access logs)")
	flag.StringVar(&cfg.ClientHeader, "client-header", cfg.ClientHeader, "header that tells the upstream which client called")
	flag.StringVar(&cfg.GroupsHeader, "groups-header", cfg.GroupsHeader, "header that passes the client's groups upstream (empty to disable)")
	flag.BoolVar(&cfg.StripKey, "strip-key", cfg.StripKey, "remove the API key before the request reaches the upstream")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, log, cfg, *grpcAddr, *httpAddr, *opsAddr, *httpPrefix, *namespace, *keysFile, *kubeconfig); err != nil {
		log.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger, cfg authz.Config, grpcAddr, httpAddr, opsAddr, httpPrefix, namespace,
	keysFile, kubeconfig string) error {
	store := keys.NewStore()
	var ready atomic.Bool
	ops := &http.Server{Addr: opsAddr, Handler: server.Ops(&ready), ReadHeaderTimeout: 5 * time.Second}
	go serveHTTP(ops, log)

	if keysFile != "" {
		if err := keys.LoadFile(keysFile, store); err != nil {
			return err
		}
	} else {
		client, err := kubeClient(kubeconfig)
		if err != nil {
			return err
		}
		if err := keys.WatchSecrets(ctx, client, namespace, store, log); err != nil {
			return err
		}
	}
	ready.Store(true)
	log.Info("keys loaded", "count", store.Len(), "version", version)

	a := authz.Authorizer{Store: store, Config: cfg}
	g := grpc.NewServer()
	authv3.RegisterAuthorizationServer(g, &server.GRPC{Authorizer: a, Log: log})
	healthpb.RegisterHealthServer(g, health.NewServer())
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return err
	}
	go func() {
		if err := g.Serve(lis); err != nil {
			log.Error("grpc server stopped", "error", err)
		}
	}()
	check := &http.Server{Addr: httpAddr, Handler: &server.HTTP{Authorizer: a, Log: log, PathPrefix: httpPrefix},
		ReadHeaderTimeout: 5 * time.Second}
	go serveHTTP(check, log)
	log.Info("serving", "grpc", grpcAddr, "http", httpAddr, "ops", opsAddr)

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g.GracefulStop()
	_ = check.Shutdown(shutdown)
	_ = ops.Shutdown(shutdown)
	return nil
}

func serveHTTP(s *http.Server, log *slog.Logger) {
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("http server stopped", "addr", s.Addr, "error", err)
	}
}

func kubeClient(kubeconfig string) (kubernetes.Interface, error) {
	var (
		cfg *rest.Config
		err error
	)
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}
