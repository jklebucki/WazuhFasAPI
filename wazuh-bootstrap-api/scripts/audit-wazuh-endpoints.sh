#!/usr/bin/env bash
set -Eeuo pipefail

api_url="${WAZUH_API_URL:-https://127.0.0.1:55000}"
default_hostname="$(hostname -s)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf -- "$temporary_directory"' EXIT

echo "Wazuh Bootstrap API endpoint audit"
echo "API: $api_url"
if command -v ss >/dev/null 2>&1; then
    if ss -ltn | awk '{print $4}' | grep -Eq '(^|:|\])55000$'; then
        echo "[OK] TCP 55000 is listening locally"
    else
        echo "[WARN] TCP 55000 was not found in the local listening-socket list"
    fi
fi

trusted_tls_code="$(curl --silent --show-error --connect-timeout 3 --max-time 10 \
    --output /dev/null --write-out '%{http_code}' "$api_url/manager/info" 2>/dev/null || true)"
if [[ "$trusted_tls_code" =~ ^(200|401|403)$ ]]; then
    echo "[OK] TLS certificate is trusted by the system CA store (HTTP $trusted_tls_code)"
else
    echo "[WARN] TLS certificate is not trusted by the system CA store or API is unreachable"
fi

read -r -p "Wazuh API username: " api_username
read -r -s -p "Wazuh API password: " api_password
echo
read -r -p "Agent hostname for exact lookup [$default_hostname]: " lookup_hostname
lookup_hostname="${lookup_hostname:-$default_hostname}"

auth_body="$temporary_directory/auth.body"
auth_code="$(curl --silent --show-error --insecure --connect-timeout 3 --max-time 15 \
    --user "$api_username:$api_password" --request POST \
    --output "$auth_body" --write-out '%{http_code}' \
    "$api_url/security/user/authenticate?raw=true" || true)"
unset api_password
if [[ "$auth_code" != "200" ]]; then
    echo "[FAIL] POST /security/user/authenticate?raw=true -> HTTP $auth_code"
    exit 1
fi

token="$(python3 - "$auth_body" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
try:
    parsed = json.loads(text)
except json.JSONDecodeError:
    parsed = text.strip('"')
if isinstance(parsed, dict):
    data = parsed.get("data")
    parsed = data.get("token") if isinstance(data, dict) else None
if not isinstance(parsed, str) or parsed.count(".") != 2:
    raise SystemExit("Authentication response did not contain a JWT")
print(parsed)
PY
)"
echo "[OK] POST /security/user/authenticate?raw=true -> HTTP 200, JWT received"

check_endpoint() {
    local label="$1"
    local path="$2"
    local body="$temporary_directory/${label}.json"
    local code
    code="$(curl --silent --show-error --insecure --connect-timeout 3 --max-time 15 \
        --header "Authorization: Bearer $token" --output "$body" --write-out '%{http_code}' \
        "$api_url$path" || true)"
    python3 - "$label" "$code" "$body" <<'PY'
import json
import pathlib
import sys

label, code, filename = sys.argv[1:]
prefix = "OK" if code == "200" else "FAIL"
try:
    body = json.loads(pathlib.Path(filename).read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    print(f"[{prefix}] {label} -> HTTP {code}, response is not valid JSON")
    raise SystemExit(0)
if not isinstance(body, dict):
    print(f"[{prefix}] {label} -> HTTP {code}, unexpected JSON shape")
    raise SystemExit(0)
error = body.get("error")
data = body.get("data")
summary = [f"HTTP {code}", f"error={error!r}"]
if isinstance(data, dict):
    total = data.get("total_affected_items")
    if isinstance(total, int):
        summary.append(f"total_affected_items={total}")
    items = data.get("affected_items")
    if isinstance(items, list) and items and label == "manager_info" and isinstance(items[0], dict):
        summary.append(f"manager_version={items[0].get('version')!r}")
print(f"[{prefix}] {label} -> " + ", ".join(summary))
PY
}

agent_select='id,name,group,status,status_code,version,ip,registerIP,lastKeepAlive,dateAdd,manager,node_name,os.platform,os.name,os.version'
encoded_hostname="$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$lookup_hostname")"
check_endpoint manager_info '/manager/info'
check_endpoint agent_lookup "/agents?name=$encoded_hostname&select=$agent_select&limit=100"
check_endpoint agents_page "/agents?select=$agent_select&sort=name&limit=500&offset=0"
check_endpoint groups_page '/groups?sort=name&limit=500&offset=0'
unset token

echo "Audit finished. Every required operation above should report [OK] and HTTP 200."
