# Cloudflare Exporter

Lightweight Prometheus exporter for Cloudflare zone analytics, written in Go. Uses the Cloudflare GraphQL Analytics API to expose HTTP request, DNS, security, and bandwidth metrics.

## Features

- Cloudflare GraphQL Analytics API (no REST API polling)
- 30+ Prometheus metrics with zone-level granularity
- Parallel data fetching per zone
- Graceful degradation (Pro+ metrics silently skipped on free plans)
- Scratch-based container image (~7MB)
- Helm chart with SecurityContext, ServiceMonitor, probes

## Quick Start

```bash
# Binary
export CF_API_KEY="your-key"
export CF_API_EMAIL="your@email.com"
export CF_ZONES="zone-id-1,zone-id-2"
./cloudflare-exporter

# Podman
podman run -e CF_API_TOKEN=your-token -e CF_ZONES=zone-id -p 8080:8080 ghcr.io/olech2412/cloudflare-exporter

# Helm
helm install cloudflare-exporter ./charts/cloudflare-exporter \
  --set cloudflareZones=zone-id \
  --set existingSecret=cloudflare-creds \
  --set serviceMonitor.enabled=true
```

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `CF_API_KEY` | yes* | | Cloudflare Global API Key |
| `CF_API_EMAIL` | yes* | | Cloudflare account email |
| `CF_API_TOKEN` | yes* | | API Token (alternative to key+email) |
| `CF_ZONES` | yes | | Comma-separated zone IDs |
| `METRICS_PORT` | no | `8080` | Port for `/metrics` endpoint |
| `SCRAPE_DELAY` | no | `300` | Time window in seconds for adaptive queries |

\* Either `CF_API_TOKEN` **or** both `CF_API_KEY` + `CF_API_EMAIL`.

## Endpoints

| Path | Description |
|---|---|
| `/metrics` | Prometheus metrics |
| `/healthz` | Liveness probe |
| `/readyz` | Readiness probe |

## Metrics

### HTTP Traffic (all plans)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_requests_total` | zone | Total HTTP requests |
| `cloudflare_zone_requests_cached` | zone | Cached requests |
| `cloudflare_zone_requests_encrypted` | zone | SSL/TLS encrypted requests |
| `cloudflare_zone_requests_status` | zone, status | Requests by HTTP status code |
| `cloudflare_zone_requests_country` | zone, country | Requests by client country |
| `cloudflare_zone_requests_content_type` | zone, content_type | Requests by content type |
| `cloudflare_zone_requests_cache_status` | zone, cache_status | Requests by cache status (hit/miss/dynamic) |
| `cloudflare_zone_requests_http_protocol` | zone, protocol | Requests by HTTP version (1.1/2/3) |
| `cloudflare_zone_requests_ssl_protocol` | zone, ssl_protocol | Requests by TLS version |
| `cloudflare_zone_requests_device_type` | zone, device_type | Requests by device (desktop/mobile) |
| `cloudflare_zone_requests_browser` | zone, browser | Requests by browser family |
| `cloudflare_zone_requests_os` | zone, os | Requests by operating system |
| `cloudflare_zone_requests_origin_status` | zone, status | Requests by origin response status |

### Security (all plans)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_requests_security_action` | zone, action | Requests by security action (block, managed_challenge, etc.) |
| `cloudflare_zone_requests_security_source` | zone, source | Requests by security source (botFight, waf, etc.) |
| `cloudflare_zone_threats_total` | zone | Total threats |
| `cloudflare_zone_threats_country` | zone, country | Threats by country |

### Bandwidth (all plans)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_bandwidth_total_bytes` | zone | Total bandwidth |
| `cloudflare_zone_bandwidth_cached_bytes` | zone | Cached bandwidth |
| `cloudflare_zone_bandwidth_encrypted_bytes` | zone | SSL/TLS encrypted bandwidth |
| `cloudflare_zone_bandwidth_country_bytes` | zone, country | Bandwidth by country |
| `cloudflare_zone_bandwidth_content_type_bytes` | zone, content_type | Bandwidth by content type |
| `cloudflare_zone_request_bytes_total` | zone | Inbound bytes (client to edge) |
| `cloudflare_zone_response_bytes_total` | zone | Outbound bytes (edge to client) |

### Visitors (all plans)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_pageviews_total` | zone | Total page views |
| `cloudflare_zone_pageviews_browser` | zone, browser | Page views by browser |
| `cloudflare_zone_unique_visitors` | zone | Unique visitors |

### DNS (all plans)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_dns_queries` | zone, query_name, query_type, response_code | DNS queries |

### Firewall (Pro+ plans)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_firewall_events_action` | zone, action | Firewall events by action |
| `cloudflare_zone_firewall_events_source` | zone, source | Firewall events by source |
| `cloudflare_zone_firewall_events_country` | zone, country | Firewall events by country |

### Health Checks (Pro+ plans)

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_health_check_events` | zone, status, origin_ip, health_check_name, region | Health check events |

### Exporter

| Metric | Labels | Description |
|---|---|---|
| `cloudflare_zone_up` | zone | Scrape success (1/0) |
| `cloudflare_scrape_duration_seconds` | | Scrape duration |

## Container Image

```bash
# Build
podman build -t cloudflare-exporter .

# Build with version tag
podman build --build-arg VERSION=1.0.0 -t cloudflare-exporter:1.0.0 .
```

Image details:
- Base: `scratch` (no OS, no shell)
- User: `65534:65534` (nobody)
- Size: ~7MB
- Read-only filesystem compatible

## Helm Chart

See [charts/cloudflare-exporter/README.md](charts/cloudflare-exporter/README.md) for full documentation.

### Minimal install with existing secret

```bash
helm install cloudflare-exporter ./charts/cloudflare-exporter \
  --set cloudflareZones="zone-id" \
  --set existingSecret="cloudflare-creds"
```

### With ServiceMonitor for kube-prometheus-stack

```bash
helm install cloudflare-exporter ./charts/cloudflare-exporter \
  --set cloudflareZones="zone-id" \
  --set existingSecret="cloudflare-creds" \
  --set serviceMonitor.enabled=true \
  --set serviceMonitor.namespace=monitoring \
  --set serviceMonitor.labels.release=kube-prometheus-stack
```

## Security

- Runs as non-root (`65534`/nobody)
- Read-only root filesystem
- All capabilities dropped
- Seccomp `RuntimeDefault` profile
- `automountServiceAccountToken: false`
- No shell in container image (scratch)
- Secrets via Kubernetes Secret references (never env inline)

## Building from source

```bash
go build -ldflags="-s -w" -o cloudflare-exporter .
```
