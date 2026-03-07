{{/*
Common labels for all resources.
*/}}
{{- define "kpod-metrics.labels" -}}
app.kubernetes.io/name: kpod-metrics
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels used in matchLabels and pod selectors.
*/}}
{{- define "kpod-metrics.selectorLabels" -}}
app.kubernetes.io/name: kpod-metrics
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
