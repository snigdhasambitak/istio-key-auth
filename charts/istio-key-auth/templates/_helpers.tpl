{{- define "ika.name" -}}{{ .Release.Name }}{{- end -}}
{{- define "ika.labels" -}}
app.kubernetes.io/name: istio-key-auth
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "ika.selector" -}}
app.kubernetes.io/name: istio-key-auth
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "ika.keysNamespace" -}}{{ default .Release.Namespace .Values.keysNamespace }}{{- end -}}
