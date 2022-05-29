{{/*
Expand the name of the chart.
*/}}
{{- define "trivy-operator-polr-adapter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "trivy-operator-polr-adapter.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "trivy-operator-polr-adapter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "trivy-operator-polr-adapter.labels" -}}
helm.sh/chart: {{ include "trivy-operator-polr-adapter.chart" . }}
{{ include "trivy-operator-polr-adapter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "trivy-operator-polr-adapter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trivy-operator-polr-adapter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "trivy-operator-polr-adapter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "trivy-operator-polr-adapter.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "trivy-operator-polr-adapter.securityContext" -}}
{{- if semverCompare "<1.19" .Capabilities.KubeVersion.Version }}
{{ toYaml (omit .Values.securityContext "seccompProfile") }}
{{- else }}
{{ toYaml .Values.securityContext }}
{{- end }}
{{- end }}
