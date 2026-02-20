# Builder Stage 🔨
FROM golang:1.25-alpine AS builder

ARG BINARY_NAME=providApp
ARG APP_VERSION=0.0.0
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETARCH

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with optimizations (TARGETARCH is automatically set by Docker Buildx)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X main.Version=${APP_VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildDate=${BUILD_DATE}" -tags=go_json \
    -trimpath \
    -o ${BINARY_NAME} ./cmd/provid-module

# Runner Stage 🏃🏻 - Using distroless for security and smaller size
FROM gcr.io/distroless/static-debian12:nonroot

ARG BINARY_NAME=providApp
ARG APP_VERSION=0.0.0
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

# Metadata labels (auto-populated by docker/metadata-action in CI)
LABEL org.opencontainers.image.title="Provid Service" \
      org.opencontainers.image.description="Provid Backend Service" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}"

WORKDIR /app

# Copy CA certificates and timezone data from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy binary from builder
COPY --from=builder /build/${BINARY_NAME} /app/providApp

# Configuration volume
VOLUME ["/app/config", "/app/logs"]

# Expose port
EXPOSE 8081

# Note: distroless/static-debian12:nonroot already runs as nonroot user (UID 65532)
# No need to explicitly set USER

# Note: Health check should be defined in docker-compose.yml
# Distroless doesn't include shell or curl/wget for health checks

ENTRYPOINT ["/app/providApp"]
