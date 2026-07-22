#!/usr/bin/env bash
set -Eeuo pipefail

install_dir=/opt/wazuh-bootstrap-api
env_file=/etc/wazuh-bootstrap-api.env
service_name=wazuh-bootstrap-api
upgrade=false
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() { echo "Usage: $0 [--upgrade]"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-nginx)
            echo "Nginx is hosted on the central proxy 192.168.21.17; it is not installed here." >&2
            exit 2
            ;;
        --upgrade) upgrade=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "This installer must run as root." >&2; exit 1; }
[[ -r /etc/os-release ]] || { echo "Cannot identify the operating system." >&2; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${ID_LIKE:-}" in
    ubuntu:*|debian:*|*:debian*) ;;
    *) echo "Only Ubuntu and Debian are supported." >&2; exit 1 ;;
esac
if $upgrade && [[ ! -d "$install_dir" ]]; then
    echo "Cannot upgrade: $install_dir does not exist." >&2
    exit 1
fi

packages=(python3 python3-venv python3-pip ca-certificates curl)
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
python3 -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12 or newer is required"' \
    || { echo "Install Python 3.12+ and rerun the installer." >&2; exit 1; }

getent group wazuh-bootstrap >/dev/null || groupadd --system wazuh-bootstrap
id wazuh-bootstrap >/dev/null 2>&1 || useradd \
    --system --gid wazuh-bootstrap --home-dir "$install_dir" --no-create-home \
    --shell /usr/sbin/nologin wazuh-bootstrap

stage_dir="$(mktemp -d /opt/wazuh-bootstrap-api.stage.XXXXXX)"
backup_dir=""
cleanup() { [[ -d "$stage_dir" ]] && rm -rf -- "$stage_dir"; }
trap cleanup EXIT
tar --exclude=.git --exclude=.venv --exclude=.env --exclude=__pycache__ \
    -C "$source_dir" -cf - . | tar -C "$stage_dir" -xf -

if [[ -d "$install_dir" ]]; then
    backup_dir="/opt/wazuh-bootstrap-api.rollback.$(date +%Y%m%d%H%M%S)"
    mv -- "$install_dir" "$backup_dir"
fi
mv -- "$stage_dir" "$install_dir"
stage_dir=""
chown -R root:wazuh-bootstrap "$install_dir"
find "$install_dir" -type d -exec chmod 0750 {} +
find "$install_dir" -type f -exec chmod 0640 {} +
chmod 0750 "$install_dir"/scripts/*.sh "$install_dir"/scripts/*.py

python3 -m venv "$install_dir/.venv"
"$install_dir/.venv/bin/python" -m pip install --disable-pip-version-check \
    --requirement "$install_dir/requirements.lock"
chown -R root:wazuh-bootstrap "$install_dir/.venv"

if [[ ! -e "$env_file" ]]; then
    install -o root -g wazuh-bootstrap -m 0640 \
        "$install_dir/deploy/env/wazuh-bootstrap-api.env.example" "$env_file"
    echo "Created $env_file. Replace every CHANGE_ME before the service can start."
else
    chown root:wazuh-bootstrap "$env_file"
    chmod 0640 "$env_file"
    echo "Preserved existing $env_file."
fi

install -o root -g root -m 0644 \
    "$install_dir/deploy/systemd/wazuh-bootstrap-api.service" \
    /etc/systemd/system/wazuh-bootstrap-api.service
systemctl daemon-reload
if ! "$install_dir/.venv/bin/python" "$install_dir/scripts/validate-config.py" \
    --env-file "$env_file" --import-app; then
    echo "Installation files are ready, but configuration is invalid." >&2
    echo "Edit $env_file, rerun validate-config.py, then rerun this installer with --upgrade." >&2
    exit 2
fi

systemctl enable --now "$service_name"
if $upgrade; then systemctl restart "$service_name"; fi

if ! "$install_dir/scripts/smoke-test.sh" --env-file "$env_file"; then
    echo "Service started but the smoke test failed." >&2
    [[ -n "$backup_dir" ]] && echo "Rollback copy is available at $backup_dir" >&2
    exit 1
fi

echo "Wazuh Bootstrap API installed successfully."
echo "Central proxy endpoint: https://wazuh.ad.citronex.pl:8443"
echo "Verify that host firewall permits TCP/8765 only from 192.168.21.17."
