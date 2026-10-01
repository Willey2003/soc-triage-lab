{{- define "soc.labels" -}}
app.kubernetes.io/part-of: soc-triage
app.kubernetes.io/instance: {{ .Release.Name }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}
{{- define "soc.image" -}}{{ .Values.image.repository }}:{{ .Values.image.tag }}{{- end }}
{{- define "soc.pvc" -}}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ .name }}
  labels: {{- include "soc.labels" .root | nindent 4 }}
spec:
  accessModes: [ReadWriteOnce]
  {{- with .root.Values.storageClassName }}
  storageClassName: {{ . }}
  {{- end }}
  resources: {requests: {storage: {{ .size }}}}
{{- end }}
