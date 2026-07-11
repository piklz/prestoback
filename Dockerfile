# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

# ARG must be declared BEFORE the COPY that brings in source files.
# This ensures a new VERSION value busts the layer cache so the build
# step always re-runs with fresh code when the tag/version changes.
ARG VERSION=dev

COPY . .

RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X 'github.com/pi/prestoback/internal/config.Version=${VERSION}'" \
    -o /prestoback ./cmd/prestoback


# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.19

# rsync + ssh for remote push; docker CLI for container stop/start + self-update
RUN apk add --no-cache rsync openssh-client ca-certificates tzdata docker-cli docker-cli-compose

WORKDIR /app
COPY --from=builder /prestoback .

VOLUME ["/data", "/volumes"]
EXPOSE 8778

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8778/healthz || exit 1

ENTRYPOINT ["/app/prestoback"]
CMD ["--port=8778", "--data=/data", "--volumes=/volumes"]