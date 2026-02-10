FROM golang:1.25-alpine AS builder

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -trimpath \
    -o cloudflare-exporter .

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /build/cloudflare-exporter /cloudflare-exporter

USER 65534:65534
EXPOSE 8080

ENTRYPOINT ["/cloudflare-exporter"]
