# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src

# FIX 1: Copy both go.mod AND go.sum
COPY go.mod go.sum ./

# FIX 2: Remove '|| true' so failures aren't swallowed
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /prestoback ./cmd/prestoback

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.19

# rsync + ssh for remote push; docker CLI for container stop/start + self-update
RUN apk add --no-cache rsync openssh-client ca-certificates tzdata docker-cli

WORKDIR /app
COPY --from=builder /prestoback .

VOLUME ["/data", "/volumes"]
EXPOSE 8765

# Docker's own health check — hits /healthz every 30s.
# If it fails 3 times in a row Docker marks the container unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8765/healthz || exit 1

ENTRYPOINT ["/app/prestoback"]
CMD ["--port=8765", "--data=/data", "--volumes=/volumes"]