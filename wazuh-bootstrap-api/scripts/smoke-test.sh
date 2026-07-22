#!/usr/bin/env bash
set -Eeuo pipefail

base_url=""
hostname="${HOSTNAME:-$(hostname -s)}"
env_file="/etc/wazuh-bootstrap-api.env"
client_key=""

usage() { echo "Usage: $0 [--base-url URL] [--hostname NAME] [--client-key KEY] [--env-file FILE]"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-url) base_url="$2"; shift 2 ;;
        --hostname) hostname="$2"; shift 2 ;;
        --client-key) client_key="$2"; shift 2 ;;
        --env-file) env_file="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

env_value() {
    local key="$1"
    local value
    value="$(sed -n "s/^${key}=//p" "$env_file" | tail -n 1)"
    if [[ "$value" == \"*\" ]]; then
        value="${value:1:${#value}-2}"
    fi
    printf '%s' "$value"
}

if [[ -r "$env_file" ]]; then
    if [[ -z "$client_key" && $EUID -eq 0 ]]; then
        client_key="$(env_value CLIENT_API_KEY)"
    fi
    if [[ -z "$base_url" ]]; then
        bind_host="$(env_value BIND_HOST)"
        bind_port="$(env_value BIND_PORT)"
        [[ "$bind_host" == "0.0.0.0" || "$bind_host" == "::" ]] && bind_host="127.0.0.1"
        base_url="http://${bind_host:-127.0.0.1}:${bind_port:-8765}"
    fi
fi
base_url="${base_url:-http://127.0.0.1:8765}"
[[ ${#client_key} -ge 32 ]] || { echo "A valid client key is required." >&2; exit 2; }

curl_common=(--fail --silent --show-error --connect-timeout 3 --max-time 15)
curl "${curl_common[@]}" "$base_url/health/live" >/dev/null
curl "${curl_common[@]}" "$base_url/health/ready" >/dev/null

curl_config="$(mktemp)"
trap 'rm -f -- "$curl_config"' EXIT
chmod 0600 "$curl_config"
printf 'header = "X-API-Key: %s"\n' "$client_key" >"$curl_config"
curl "${curl_common[@]}" --config "$curl_config" "$base_url/api/v1/manifest" >/dev/null
curl "${curl_common[@]}" --config "$curl_config" "$base_url/api/v1/agents/$hostname" >/dev/null
echo "Smoke test passed."
