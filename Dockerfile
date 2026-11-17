FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/istio-key-auth ./cmd/istio-key-auth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/istio-key-auth /istio-key-auth
USER 65532:65532
EXPOSE 9001 8000 9090
ENTRYPOINT ["/istio-key-auth"]
