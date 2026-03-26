{{- define "auto-updater.name" -}}
auto-updater
{{- end -}}

{{- define "auto-updater.fullname" -}}
{{- include "auto-updater.name" . -}}
{{- end -}}

{{- define "auto-updater.labels" -}}
app.kubernetes.io/name: {{ include "auto-updater.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "auto-updater.image" -}}
{{ printf "%s:%s" .Values.image.repository .Values.image.tag }}
{{- end -}}

{{- define "auto-updater.singboxImage" -}}
{{ printf "%s:%s" .Values.singboxImage.repository .Values.singboxImage.tag }}
{{- end -}}
