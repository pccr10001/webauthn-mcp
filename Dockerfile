# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/webauthn-mcp .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 appuser \
    && mkdir -p /app /data/tokens \
    && chown -R appuser:appuser /app /data

WORKDIR /app

COPY --from=builder /out/webauthn-mcp /usr/local/bin/webauthn-mcp
COPY config.yaml /app/config.yaml

ENV WEBAUTHN_MCP_STORAGE_PATH=/data/tokens

EXPOSE 8080

USER appuser

ENTRYPOINT ["/usr/local/bin/webauthn-mcp"]
