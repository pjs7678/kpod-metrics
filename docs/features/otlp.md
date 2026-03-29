# OTLP Export

Push metrics to any OpenTelemetry-compatible collector alongside Prometheus scraping.

## Configuration

```yaml
otlp:
  enabled: true
  endpoint: "http://otel-collector:4318/v1/metrics"
  headers:
    api-key: "my-api-key"
  step: 60000   # push interval in ms
```

When enabled, an `OtlpMeterRegistry` is created that pushes all kpod metrics via OTLP/HTTP. This works **in parallel** with Prometheus scraping — both registries receive the same metrics.

## Using a Secret

For production, use an existing Kubernetes Secret for sensitive headers:

```yaml
otlp:
  enabled: true
  endpoint: "http://otel-collector:4318/v1/metrics"
  existingSecret: "otlp-credentials"
```

The Secret should contain keys matching header names:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: otlp-credentials
type: Opaque
data:
  api-key: <base64-encoded-value>
```

## Compatible Backends

OTLP export works with any OpenTelemetry-compatible backend:

- Grafana Cloud / Grafana Mimir
- Datadog
- New Relic
- Honeycomb
- Jaeger
- AWS CloudWatch (via ADOT collector)
- Google Cloud Monitoring (via OTel collector)
