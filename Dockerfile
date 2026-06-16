# syntax=docker/dockerfile:1.7

FROM golang:1.24-alpine AS builder
WORKDIR /src

ARG GOPROXY=https://goproxy.cn,direct
ARG GOSUMDB=sum.golang.google.cn

# Install build deps for CGO-enabled drivers (if any) and TLS certs.
RUN apk add --no-cache build-base ca-certificates git openssh-client

ENV GOPROXY=${GOPROXY}
ENV GOSUMDB=${GOSUMDB}

COPY backend/go.mod backend/go.sum ./backend/
WORKDIR /src/backend
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY backend/ ./
RUN --mount=type=cache,target=/go/pkg/mod CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/modern-dns ./main.go

FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

# Runtime binary + default config directory.
COPY --from=builder /out/modern-dns /app/modern-dns
COPY backend/config /app/config
COPY backend/certs /app/certs

EXPOSE 8080 53/tcp 53/udp

ENTRYPOINT ["/app/modern-dns"]
