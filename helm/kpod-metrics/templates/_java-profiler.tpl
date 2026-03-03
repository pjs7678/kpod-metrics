{{/*
Pyroscope Java agent helper templates.
Usage: Include these in workload charts that need Java CPU + allocation profiling.

Example in a Deployment:
  spec:
    template:
      spec:
        initContainers:
          {{- include "kpod.java-profiler.initContainer" .Values.javaProfiling | nindent 8 }}
        containers:
          - name: myapp
            env:
              {{- include "kpod.java-profiler.env" .Values.javaProfiling | nindent 12 }}
            volumeMounts:
              {{- include "kpod.java-profiler.volumeMount" .Values.javaProfiling | nindent 12 }}
        volumes:
          {{- include "kpod.java-profiler.volume" .Values.javaProfiling | nindent 8 }}
*/}}

{{- define "kpod.java-profiler.initContainer" -}}
{{- if .enabled }}
- name: pyroscope-java-agent
  image: {{ .image | default "grafana/pyroscope-java:0.14.0" }}
  command: ["cp", "/pyroscope.jar", "/pyroscope-agent/pyroscope.jar"]
  volumeMounts:
    - name: pyroscope-agent
      mountPath: /pyroscope-agent
{{- end }}
{{- end }}

{{- define "kpod.java-profiler.env" -}}
{{- if .enabled }}
- name: JAVA_TOOL_OPTIONS
  value: >-
    -javaagent:/pyroscope-agent/pyroscope.jar
    -Dpyroscope.application.name={{ .appName | default "java-app" }}
    -Dpyroscope.server.address={{ .pyroscopeEndpoint | default "http://pyroscope:4040" }}
    -Dpyroscope.format=jfr
    {{- if .tenantId }}
    -Dpyroscope.tenantID={{ .tenantId }}
    {{- end }}
    {{- if .authToken }}
    -Dpyroscope.auth.token={{ .authToken }}
    {{- end }}
    {{- if .extraJavaOpts }}
    {{ .extraJavaOpts }}
    {{- end }}
{{- end }}
{{- end }}

{{- define "kpod.java-profiler.volumeMount" -}}
{{- if .enabled }}
- name: pyroscope-agent
  mountPath: /pyroscope-agent
  readOnly: true
{{- end }}
{{- end }}

{{- define "kpod.java-profiler.volume" -}}
{{- if .enabled }}
- name: pyroscope-agent
  emptyDir: {}
{{- end }}
{{- end }}
