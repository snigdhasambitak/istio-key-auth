IMAGE ?= ghcr.io/snigdhasambitak/istio-key-auth
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test lint image chart-lint run

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/istio-key-auth ./cmd/istio-key-auth

test:
	go test -race ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

chart-lint:
	helm lint charts/istio-key-auth

run: build
	./bin/istio-key-auth --keys-file examples/keys.yaml
