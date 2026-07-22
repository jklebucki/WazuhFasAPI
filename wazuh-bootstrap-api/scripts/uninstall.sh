#!/usr/bin/env bash
set -Eeuo pipefail

purge=false
usage() { echo "Usage: $0 [--purge]"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge) purge=true; shift ;;
        --remove-nginx-config)
            echo "Nginx is managed separately on central proxy 192.168.21.17." >&2
            exit 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[[ $EUID -eq 0 ]] || { echo "This uninstaller must run as root." >&2; exit 1; }

systemctl disable --now wazuh-bootstrap-api 2>/dev/null || true
rm -f -- /etc/systemd/system/wazuh-bootstrap-api.service
systemctl daemon-reload
if [[ -d /opt/wazuh-bootstrap-api ]]; then
    rm -rf -- /opt/wazuh-bootstrap-api
    echo "Removed /opt/wazuh-bootstrap-api."
fi
if $purge; then
    rm -f -- /etc/wazuh-bootstrap-api.env
    echo "Removed /etc/wazuh-bootstrap-api.env (not recoverable unless backed up)."
else
    echo "Preserved /etc/wazuh-bootstrap-api.env; use --purge to remove it."
fi
echo "Wazuh Manager and all of its files were left unchanged."
