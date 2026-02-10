# cloudflare-exporter

Prometheus exporter for Cloudflare zone analytics via GraphQL API.

## Installing the Chart

```bash
helm install cloudflare-exporter ./charts/cloudflare-exporter \
  --set cloudflareZones="your-zone-id" \
  --set existingSecret="cloudflare-creds"
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| replicaCount | int | `1` | Number of replicas |
| image.repository | string | `"ghcr.io/olech2412/cloudflare-exporter"` | Container image repository |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| image.tag | string | `""` | Overrides the image tag (default: chart appVersion) |
| imagePullSecrets | list | `[]` | Image pull secrets for private registries |
| nameOverride | string | `""` | Override the release name |
| fullnameOverride | string | `""` | Override the full release name |
| cloudflareZones | string | `""` | Cloudflare zone IDs (comma-separated) |
| existingSecret | string | `""` | Name of an existing Secret containing Cloudflare credentials. The secret must have keys `CF_API_KEY` and `CF_API_EMAIL`, or `CF_API_TOKEN`. |
| cloudflareApiKey | string | `""` | Inline credentials (only used if existingSecret is empty). NOT recommended for production. |
| cloudflareApiEmail | string | `""` | Inline credentials (only used if existingSecret is empty). NOT recommended for production. |
| cloudflareApiToken | string | `""` | Inline credentials (only used if existingSecret is empty). NOT recommended for production. |
| metricsPort | int | `8080` | Port for the metrics endpoint |
| scrapeDelay | int | `300` | How far back (in seconds) to query Cloudflare analytics |
| serviceAccount.create | bool | `true` | Create a ServiceAccount |
| serviceAccount.annotations | object | `{}` | Annotations for the ServiceAccount |
| serviceAccount.name | string | `""` | Override ServiceAccount name |
| podAnnotations | object | `{}` | Annotations for the Pod |
| podLabels | object | `{}` | Labels for the Pod |
| podSecurityContext.runAsNonRoot | bool | `true` | Run as non-root |
| podSecurityContext.runAsUser | int | `65534` | User ID |
| podSecurityContext.runAsGroup | int | `65534` | Group ID |
| podSecurityContext.fsGroup | int | `65534` | FS group |
| podSecurityContext.seccompProfile.type | string | `"RuntimeDefault"` | Seccomp profile |
| securityContext.allowPrivilegeEscalation | bool | `false` | Disallow privilege escalation |
| securityContext.readOnlyRootFilesystem | bool | `true` | Read-only root filesystem |
| securityContext.capabilities.drop | list | `["ALL"]` | Drop all capabilities |
| service.type | string | `"ClusterIP"` | Service type |
| service.port | int | `8080` | Service port |
| serviceMonitor.enabled | bool | `false` | Create a Prometheus ServiceMonitor |
| serviceMonitor.namespace | string | `""` | Namespace for the ServiceMonitor (defaults to release namespace) |
| serviceMonitor.labels | object | `{}` | Additional labels for the ServiceMonitor (e.g. release: kube-prometheus-stack) |
| serviceMonitor.interval | string | `"60s"` | Scrape interval |
| serviceMonitor.scrapeTimeout | string | `"30s"` | Scrape timeout |
| resources.limits.cpu | string | `"100m"` | CPU limit |
| resources.limits.memory | string | `"128Mi"` | Memory limit |
| resources.requests.cpu | string | `"10m"` | CPU request |
| resources.requests.memory | string | `"32Mi"` | Memory request |
| nodeSelector | object | `{}` | Node selector |
| tolerations | list | `[]` | Tolerations |
| affinity | object | `{}` | Affinity rules |

## Authentication

### Option 1: Existing Secret (recommended)

Create a secret manually or via external-secrets:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cloudflare-creds
type: Opaque
stringData:
  CF_API_KEY: "your-global-api-key"
  CF_API_EMAIL: "your@email.com"
```

Or with API Token:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cloudflare-creds
type: Opaque
stringData:
  CF_API_TOKEN: "your-api-token"
```

Then reference it:

```yaml
existingSecret: cloudflare-creds
```

### Option 2: Inline (not recommended for production)

```yaml
cloudflareApiToken: "your-api-token"
```

## ServiceMonitor

For kube-prometheus-stack:

```yaml
serviceMonitor:
  enabled: true
  namespace: monitoring
  labels:
    release: kube-prometheus-stack
  interval: 60s
  scrapeTimeout: 30s
```

## Security Hardening

This chart applies the following security defaults:

- Non-root user (65534/nobody)
- Read-only root filesystem
- All capabilities dropped
- Seccomp RuntimeDefault profile
- automountServiceAccountToken disabled
- No privilege escalation
