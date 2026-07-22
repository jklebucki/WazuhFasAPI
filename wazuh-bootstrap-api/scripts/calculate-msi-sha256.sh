#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <https-msi-url>" >&2
    exit 2
fi
[[ "$1" == https://* ]] || { echo "Only HTTPS URLs are accepted." >&2; exit 2; }

temporary_file="$(mktemp --suffix=.msi)"
trap 'rm -f -- "$temporary_file"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$temporary_file" "$1"
sha256sum "$temporary_file" | awk '{print tolower($1)}'
