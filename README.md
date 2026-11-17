# istio-key-auth

API key authorization for Istio. It plugs into Istio as an external authorizer (Envoy `ext_authz`), reads keys from
labelled Kubernetes Secrets, and lets a request through only when it carries a known key that may call that host,
path and method.

```
caller ── x-api-key: 3f9c…e1 ──> Istio gateway or sidecar ──> your service
                                        │                       ▲
                                        │ ext_authz             │ x-api-client: mobile-app
                                        ▼                       │ (the key itself is removed)
                                  istio-key-auth  ── allowed ───┘
                                        │
                                        └── denied: 401 missing, invalid or expired key
                                                    403 key may not call this host, path or method
```

## Why

Istio checks JWTs out of the box, but many callers cannot get a token: partner systems, scripts, webhook senders,
devices. They send a static API key instead. Envoy has an API key filter, but it is not in Istio's proxy build and it
holds the keys in plain text in the gateway config. istio-key-auth keeps keys in Secrets, compares SHA-256 hashes in
constant time, and never logs a key.

## How it differs from Authorino

[Authorino](https://github.com/Kuadrant/authorino) is a general authorization engine: JWT, OAuth2 introspection, OPA,
API keys and more, configured through its own `AuthConfig` resource per API. istio-key-auth does one thing: API keys.

| | istio-key-auth | Authorino |
| --- | --- | --- |
| Scope | API keys only | Many identity and policy sources |
| Configuration | Labels and annotations on the key's Secret, plus Istio's own `AuthorizationPolicy` | `AuthConfig` custom resource per API |
| Custom resources to install | None | `AuthConfig`, and usually its operator |

Pick Authorino when you need more than API keys; pick istio-key-auth when API keys are all you need and you want
nothing beyond a Deployment and a few Secrets.

## Quick start

1. Install the authorizer:

   ```sh
   helm install istio-key-auth oci://ghcr.io/snigdhasambitak/charts/istio-key-auth \
     --namespace istio-key-auth --create-namespace
   ```

   Or use the chart attached to each [release](https://github.com/snigdhasambitak/istio-key-auth/releases).

2. Register it with Istio as an extension provider, in the mesh config
   ([examples/mesh-config.yaml](examples/mesh-config.yaml)):

   ```yaml
   meshConfig:
     extensionProviders:
       - name: istio-key-auth
         envoyExtAuthzGrpc:
           service: istio-key-auth.istio-key-auth.svc.cluster.local
           port: 9001
   ```

3. Create a key ([examples/api-key-secret.yaml](examples/api-key-secret.yaml)):

   ```sh
   kubectl -n istio-key-auth create secret generic mobile-app \
     --from-literal=api-key="$(openssl rand -hex 32)"
   kubectl -n istio-key-auth label secret mobile-app istio-key-auth.io/api-key=true
   ```

4. Require a key where you want one, with an `AuthorizationPolicy` using the `CUSTOM` action. On a workload
   ([examples/authorization-policy.yaml](examples/authorization-policy.yaml)) or at the ingress gateway
   ([examples/ingress-gateway-policy.yaml](examples/ingress-gateway-policy.yaml)):

   ```yaml
   apiVersion: security.istio.io/v1
   kind: AuthorizationPolicy
   metadata:
     name: require-api-key
     namespace: shop
   spec:
     selector:
       matchLabels:
         app: orders
     action: CUSTOM
     provider:
       name: istio-key-auth
     rules:
       - to:
           - operation:
               notPaths: ["/healthz"]
   ```

5. Call it:

   ```sh
   curl -H "x-api-key: $KEY" https://orders.example.com/v1/orders      # 200, upstream sees x-api-client: mobile-app
   curl https://orders.example.com/v1/orders                           # 401 {"error":"missing api key"}
   ```

## Keys

A key is a Secret with the label `istio-key-auth.io/api-key: "true"`. Every data entry named `api-key` or
`api-key-<suffix>` is a valid key for the same client. Changes take effect within seconds, without a restart.

| Annotation | Meaning | Default |
| --- | --- | --- |
| `istio-key-auth.io/client` | Client name sent upstream and used in metrics | The Secret's name |
| `istio-key-auth.io/hosts` | Hosts the key may call, comma separated; `*.example.com` matches subdomains | Any host |
| `istio-key-auth.io/path-prefixes` | Path prefixes the key may call | Any path |
| `istio-key-auth.io/methods` | HTTP methods the key may use, for example `GET, HEAD` for a read-only key | Any method |
| `istio-key-auth.io/groups` | Groups sent upstream in `x-api-client-groups`, for the application or another Istio policy | None |
| `istio-key-auth.io/expires-at` | RFC 3339 time after which the key is refused with 401 | Never |

**Rotating a key without downtime:** add `api-key-next` to the Secret, move the client to the new key, then remove
the old `api-key`.

**Where the key is read from**, in order: the `x-api-key` header, `Authorization: ApiKey <key>`, and, only when
`--key-query-param` is set, a query parameter. Keys in URLs end up in access logs, so the query parameter is off by
default and meant for callers that cannot set headers. The key is removed from the request before it reaches the
upstream (`--strip-key`).

Outside Kubernetes, `--keys-file` reads keys from a YAML file instead ([examples/keys.yaml](examples/keys.yaml)).

## Configuration

| Flag | Chart value | Default | Meaning |
| --- | --- | --- | --- |
| `--namespace` | `keysNamespace`, `clusterWide` | Release namespace | Namespace whose Secrets hold keys; empty reads all and needs `clusterWide: true` |
| `--key-header` | `keyHeader` | `x-api-key` | Header that carries the key |
| `--authorization-scheme` | `authorizationScheme` | `ApiKey` | Also accept `Authorization: <scheme> <key>`; empty disables |
| `--key-query-param` | `keyQueryParam` | empty | Also accept the key as this query parameter |
| `--client-header` | `clientHeader` | `x-api-client` | Header that tells the upstream which client called |
| `--groups-header` | `groupsHeader` | `x-api-client-groups` | Header that passes the client's groups upstream |
| `--strip-key` | `stripKey` | `true` | Remove the key before the request reaches the upstream |
| `--http-path-prefix` | `httpPathPrefix` | empty | `pathPrefix` of an `envoyExtAuthzHttp` provider |
| `--grpc-addr`, `--http-addr`, `--ops-addr` | | `:9001`, `:8000`, `:9090` | Listen addresses |

The gRPC provider is preferred. The HTTP provider (`envoyExtAuthzHttp`) works too, but Envoy forwards only the
headers listed in `includeRequestHeadersInCheck` and passes back only those in `headersToUpstreamOnAllow`, and it
cannot remove a query parameter.

## Operations

- `/healthz` and `/readyz` on the ops port. Ready means the first full list of Secrets has loaded, so a restarting
  authorizer never refuses valid keys because it has not read them yet.
- `/metrics`: `istio_key_auth_decisions_total{transport, result, client}`, where `result` is `allowed`,
  `unauthenticated` or `forbidden`.
- Logs are JSON. Denials are logged with host, path, status, reason and client; keys never are.

## Security notes

- Only SHA-256 hashes of keys are kept in memory, and every lookup compares all hashes in constant time.
- Use long random keys (`openssl rand -hex 32`). The authorizer does not rate-limit guesses; put Istio or Envoy
  rate limiting in front of public endpoints.
- By default the chart reads Secrets in its own namespace only. `clusterWide: true` grants read access to Secrets in
  every namespace, which is broad; prefer one namespace for keys.
- Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Development

```sh
make test        # go test -race ./...
make lint        # go vet and gofmt
make run         # run locally with examples/keys.yaml
curl -s -H 'x-api-key: dev-key-change-me' localhost:8000/anything -o /dev/null -w '%{http_code}\n'
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [RELEASE.md](RELEASE.md).

## License

Apache 2.0, see [LICENSE](LICENSE).
