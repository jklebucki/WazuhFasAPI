#!/usr/bin/env bash
set -Eeuo pipefail

default_url="https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi"
url="$default_url"
output_file="wazuh-agent-4.14.7-1.sha256.txt"

usage() {
    cat <<'EOF'
Usage: fetch-wazuh-agent-sha256.sh [--url URL] [--output FILE]

Downloads a Wazuh Windows MSI over HTTPS, calculates its SHA-256 and writes a
dotenv-compatible TARGET_AGENT_SHA256 line to the output file.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            url="$2"
            shift 2
            ;;
        --output)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            output_file="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

[[ "$url" == https://packages.wazuh.com/* ]] || {
    echo "Only HTTPS downloads from packages.wazuh.com are allowed." >&2
    exit 2
}
command -v curl >/dev/null || { echo "curl is required." >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "sha256sum is required." >&2; exit 1; }

output_dir="$(dirname -- "$output_file")"
output_name="$(basename -- "$output_file")"
[[ -d "$output_dir" ]] || { echo "Output directory does not exist: $output_dir" >&2; exit 1; }

work_dir="$(mktemp -d)"
temporary_output=""
cleanup() {
    [[ -n "$temporary_output" && -f "$temporary_output" ]] && rm -f -- "$temporary_output"
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

package_file="$work_dir/wazuh-agent.msi"
curl --fail --location --proto '=https' --tlsv1.2 --output "$package_file" "$url"
sha256="$(sha256sum "$package_file" | awk '{print $1}')"

temporary_output="$(mktemp "$output_dir/.${output_name}.XXXXXX")"
{
    printf '# Source MSI: %s\n' "$url"
    printf 'TARGET_AGENT_SHA256=%s\n' "$sha256"
} > "$temporary_output"
mv -f -- "$temporary_output" "$output_file"
temporary_output=""

printf 'SHA-256 written to %s\n' "$output_file"
printf '%s\n' "$sha256"
