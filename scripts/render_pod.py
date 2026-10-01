#!/usr/bin/env python3
"""Render deploy/podman/soc-triage-pod.yaml (Pod + PVCs + ConfigMaps) for `podman kube play`.

Every port is published on 127.0.0.1 only; reach them with an SSH tunnel.
The Grafana admin password is a placeholder that scripts/lab.sh fills in at play time.
"""
import json
import os

import yaml

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
P = os.path.join(ROOT, "deploy/podman")

IMAGES = {
    "ollama": "docker.io/ollama/ollama:0.34.4",
    "app": "localhost/soc-triage:0.1",
    "prometheus": "docker.io/prom/prometheus:v3.14.0",
    "grafana": "docker.io/grafana/grafana:13.2.2",
}
PORTS = {"api": 18090, "prometheus": 19090, "grafana": 13000}


def read(name):
    with open(os.path.join(P, name)) as f:
        return f.read()


def cm(name, data):
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": data}


def pvc(name, size):
    return {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": name},
            "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": size}}}}


def port(container, host):
    return [{"containerPort": container, "hostPort": host, "hostIP": "127.0.0.1"}]


def env(**kv):
    return [{"name": k, "value": str(v)} for k, v in kv.items()]


datasource = {"apiVersion": 1, "datasources": [{"name": "Prometheus", "uid": "prom", "type": "prometheus",
                                                "access": "proxy", "url": "http://127.0.0.1:9090", "isDefault": True}]}
provider = {"apiVersion": 1, "providers": [{"name": "soc", "folder": "SOC", "type": "file",
                                            "options": {"path": "/var/lib/grafana/dashboards"}}]}

pod = {
    "apiVersion": "v1", "kind": "Pod",
    "metadata": {"name": "soc-triage", "labels": {"app": "soc-triage"}},
    "spec": {
        "restartPolicy": "Always",
        "containers": [
            {"name": "ollama", "image": IMAGES["ollama"],
             "env": env(OLLAMA_HOST="127.0.0.1:11434", OLLAMA_KEEP_ALIVE="60m", OLLAMA_NUM_PARALLEL=1, OLLAMA_MAX_LOADED_MODELS=1),
             "resources": {"limits": {"cpu": "6", "memory": "6Gi"}},
             "volumeMounts": [{"name": "ollama-models", "mountPath": "/root/.ollama"}]},
            {"name": "api", "image": IMAGES["app"], "imagePullPolicy": "Never",
             "env": env(OLLAMA_URL="http://127.0.0.1:11434", SOC_MODEL="qwen2.5:1.5b", SOC_MODE="hybrid", SOC_DB="/data/cases.db"),
             "ports": port(8090, PORTS["api"]),
             "resources": {"limits": {"cpu": "1", "memory": "512Mi"}},
             "volumeMounts": [{"name": "soc-data", "mountPath": "/data"}]},
            {"name": "feeder", "image": IMAGES["app"], "imagePullPolicy": "Never",
             "command": ["python", "-m", "app.feeder"],
             "env": env(SOC_API="http://127.0.0.1:8090", FEED_INTERVAL_S=30, FEED_BATCH=1),
             "resources": {"limits": {"cpu": "250m", "memory": "128Mi"}}},
            {"name": "prometheus", "image": IMAGES["prometheus"],
             "args": ["--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus",
                      "--storage.tsdb.retention.time=7d", "--web.listen-address=0.0.0.0:9090"],
             "ports": port(9090, PORTS["prometheus"]),
             "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}},
             "volumeMounts": [{"name": "prom-config", "mountPath": "/etc/prometheus"},
                              {"name": "prom-data", "mountPath": "/prometheus"}]},
            {"name": "grafana", "image": IMAGES["grafana"],
             "env": env(GF_SERVER_HTTP_PORT=3000, GF_SECURITY_ADMIN_PASSWORD="__GRAFANA_ADMIN_PASSWORD__",
                        GF_AUTH_ANONYMOUS_ENABLED="true", GF_AUTH_ANONYMOUS_ORG_ROLE="Viewer",
                        GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH="/var/lib/grafana/dashboards/soc-triage-dashboard.json",
                        GF_ANALYTICS_REPORTING_ENABLED="false", GF_ANALYTICS_CHECK_FOR_UPDATES="false",
                        GF_NEWS_NEWS_FEED_ENABLED="false"),
             "ports": port(3000, PORTS["grafana"]),
             "resources": {"limits": {"cpu": "500m", "memory": "768Mi"}},
             "volumeMounts": [{"name": "grafana-datasources", "mountPath": "/etc/grafana/provisioning/datasources"},
                              {"name": "grafana-providers", "mountPath": "/etc/grafana/provisioning/dashboards"},
                              {"name": "grafana-dashboards", "mountPath": "/var/lib/grafana/dashboards"}]},
        ],
        "volumes": [
            {"name": "ollama-models", "persistentVolumeClaim": {"claimName": "soc-ollama-models"}},
            {"name": "soc-data", "persistentVolumeClaim": {"claimName": "soc-data"}},
            {"name": "prom-data", "persistentVolumeClaim": {"claimName": "soc-prom-data"}},
            {"name": "prom-config", "configMap": {"name": "soc-prom-config"}},
            {"name": "grafana-datasources", "configMap": {"name": "soc-grafana-datasources"}},
            {"name": "grafana-providers", "configMap": {"name": "soc-grafana-providers"}},
            {"name": "grafana-dashboards", "configMap": {"name": "soc-grafana-dashboards"}},
        ],
    },
}

docs = [
    pvc("soc-ollama-models", "5Gi"), pvc("soc-data", "1Gi"), pvc("soc-prom-data", "2Gi"),
    cm("soc-prom-config", {"prometheus.yml": read("prometheus.yml")}),
    cm("soc-grafana-datasources", {"prometheus.yaml": yaml.safe_dump(datasource, sort_keys=False)}),
    cm("soc-grafana-providers", {"soc.yaml": yaml.safe_dump(provider, sort_keys=False)}),
    cm("soc-grafana-dashboards", {"soc-triage-dashboard.json": json.dumps(json.loads(read("grafana/soc-triage-dashboard.json")))}),
    pod,
]
out = os.path.join(P, "soc-triage-pod.yaml")
with open(out, "w") as f:
    f.write("# Generated by scripts/render_pod.py. Run with scripts/lab.sh up (fills the Grafana password).\n")
    yaml.safe_dump_all(docs, f, sort_keys=False, width=200)
print(f"wrote {os.path.relpath(out, ROOT)}")
