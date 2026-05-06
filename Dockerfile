# Identity service — multi-arch standalone build.
#
# Build:
#   docker build -t identity .
#
# Run:
#   docker run -p 80:80 -p 9090:9090 -e GATEWAY_ENTDB_ADDRESS=entdb:50051 identity

# go.mod requires go 1.25.0; GOTOOLCHAIN=auto fetches the right toolchain.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ENV GOTOOLCHAIN=auto

RUN apk add --no-cache ca-certificates git

WORKDIR /app

# Cache deps
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY cmd/    ./cmd/
COPY internal/ ./internal/
COPY pkg/    ./pkg/
COPY gen/    ./gen/

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build \
      -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT" \
      -o /bin/identity \
      ./cmd/identity

# Runtime stage — distroless static, pinned by digest for supply-chain integrity.
# Tag at pin time: nonroot. Refresh with `crane digest gcr.io/distroless/static-debian12:nonroot`.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1 AS server

COPY --from=builder /bin/identity /bin/identity

EXPOSE 80 9090

ENTRYPOINT ["/bin/identity"]
