# Identity service — multi-arch standalone build.
#
# Build:
#   docker build -t identity .
#
# Run:
#   docker run -p 80:80 -p 9090:9090 -e GATEWAY_ENTDB_ADDRESS=entdb:50051 identity

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine3.23 AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/    ./cmd/
COPY internal/ ./internal/
COPY pkg/    ./pkg/
COPY gen/    ./gen/

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build \
      -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT" \
      -o /bin/identity \
      ./cmd/identity

FROM scratch AS server

COPY --from=builder /bin/identity /bin/identity
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE 80 9090

USER 65532:65532
ENTRYPOINT ["/bin/identity"]
