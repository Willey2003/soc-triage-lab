#!/usr/bin/env bash
# Private AI-powered SOC triage lab: rootless podman, everything on 127.0.0.1.
#   scripts/lab.sh up | status | eval [N] [modes] | test | logs [container] | tunnel | down | purge | push
set -euo pipefail
cd "$(dirname "$0")/.."
POD=soc-triage
IMAGE=localhost/soc-triage:0.1
MODEL="${SOC_MODEL:-qwen2.5:1.5b}"
STATE="$HOME/.soc-triage"
say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

rendered() {
  mkdir -p "$STATE"; chmod 700 "$STATE"
  [[ -s "$STATE/grafana-admin" ]] || { python3 -c 'import secrets; print(secrets.token_urlsafe(18))' > "$STATE/grafana-admin"; chmod 600 "$STATE/grafana-admin"; }
  umask 077
  sed "s|__GRAFANA_ADMIN_PASSWORD__|$(cat "$STATE/grafana-admin")|" deploy/podman/soc-triage-pod.yaml > "$STATE/pod.yaml"
  echo "$STATE/pod.yaml"
}

wait_ready() {
  for _ in $(seq 1 60); do
    curl -fsS -o /dev/null "http://127.0.0.1:18090/readyz" && return 0
    sleep 5
  done
  echo "API not ready after 5 minutes"; return 1
}

case "${1:-help}" in
  up)
    say "building $IMAGE"
    podman build -q -t "$IMAGE" -f Containerfile . >/dev/null
    say "podman kube play (ports on 127.0.0.1 only)"
    podman kube play --replace "$(rendered)" >/dev/null
    say "pulling $MODEL into the ollama container (first time ~1 GB)"
    podman exec "$POD-ollama" ollama pull "$MODEL" >/dev/null 2>&1
    wait_ready && say "ready"
    "$0" status ;;
  status)
    podman pod ps --filter name="$POD"
    podman ps --pod --filter pod="$POD" --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
    curl -fsS http://127.0.0.1:18090/stats 2>/dev/null && echo || echo "API not reachable"
    echo "API/UI     http://127.0.0.1:18090"
    echo "Grafana    http://127.0.0.1:13000   (anonymous viewer; admin password in $STATE/grafana-admin)"
    echo "Prometheus http://127.0.0.1:19090" ;;
  eval)
    N="${2:-120}"; MODES="${3:-rules,llm,hybrid}"
    say "offline eval: $N labelled alerts through rules, llm, hybrid (CPU model: expect several minutes)"
    podman stop -t 2 "$POD-feeder" >/dev/null 2>&1 || true    # the live feed would compete for the CPU model
    podman exec "$POD-api" python -m eval.run_eval --n "$N" --modes "$MODES" --merge --out /srv/eval/results
    podman start "$POD-feeder" >/dev/null
    mkdir -p eval/results
    podman cp "$POD-api:/srv/eval/results/latest.json" eval/results/latest.json
    podman cp "$POD-api:/srv/eval/results/latest.md" eval/results/latest.md
    say "results in eval/results/latest.md" ;;
  test)
    podman run --rm "$IMAGE" python -m pytest -q ;;
  logs)
    podman logs --tail 50 "$POD-${2:-api}" ;;
  tunnel)
    echo "From your workstation (keeps the lab on localhost):"
    echo "  ssh -N -L 18090:127.0.0.1:18090 -L 13000:127.0.0.1:13000 -L 19090:127.0.0.1:19090 $(id -un)@$(hostname -I | awk '{print $1}')" ;;
  down)
    podman kube down "$STATE/pod.yaml" ;;
  purge)
    podman kube down --force "$STATE/pod.yaml" || true
    podman rmi "$IMAGE" 2>/dev/null || true ;;
  push)
    # Token is read from ~/.github_token (mode 600) and passed via environment, never on the command line or in .git/config.
    [[ -s "$HOME/.github_token" ]] || { echo "~/.github_token missing"; exit 1; }
    hdr="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$(tr -d '\r\n' < "$HOME/.github_token")" | base64 -w0)"
    GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="http.https://github.com/.extraheader" GIT_CONFIG_VALUE_0="$hdr" \
      git push "${2:-origin}" "${3:-main}" ;;
  *) sed -n '2,3p' "$0" ;;
esac
