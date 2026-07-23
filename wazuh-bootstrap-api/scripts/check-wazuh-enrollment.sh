#!/usr/bin/env bash
set -Eeuo pipefail

config_file="/var/ossec/etc/ossec.conf"
password_file="/var/ossec/etc/authd.pass"
expected_password_file=""

usage() {
    cat <<'EOF'
Usage: sudo ./scripts/check-wazuh-enrollment.sh [options]

Validates Wazuh enrollment password configuration without printing the password
or creating an agent record.

Options:
  --config FILE                 Wazuh manager configuration
  --password-file FILE          Manager authd password file
  --expected-password-file FILE Compare with another protected one-line file
  -h, --help                    Show help
EOF
}

while (($# > 0)); do
    case "$1" in
        --config)
            config_file="${2:?Missing value for --config}"
            shift 2
            ;;
        --password-file)
            password_file="${2:?Missing value for --password-file}"
            shift 2
            ;;
        --expected-password-file)
            expected_password_file="${2:?Missing value for --expected-password-file}"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ((EUID != 0)); then
    printf 'Run this check as root (for example with sudo).\n' >&2
    exit 2
fi

failures=0
warnings=0

pass() {
    printf 'PASS: %s\n' "$1"
}

warn() {
    printf 'WARN: %s\n' "$1" >&2
    warnings=$((warnings + 1))
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

auth_value() {
    local element="$1"
    awk -v element="$element" '
        /<auth>/ { in_auth = 1 }
        in_auth {
            pattern = "<" element ">[^<]*</" element ">"
            if (match($0, pattern)) {
                value = substr($0, RSTART, RLENGTH)
                sub("^<" element ">", "", value)
                sub("</" element ">$", "", value)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                print value
            }
        }
        /<\/auth>/ { in_auth = 0 }
    ' "$config_file"
}

if [[ ! -f "$config_file" ]]; then
    fail "Manager configuration does not exist: $config_file"
else
    disabled="$(auth_value disabled)"
    use_password="$(auth_value use_password)"
    enrollment_port="$(auth_value port)"

    [[ "$disabled" == "no" ]] \
        && pass "Enrollment service is enabled in ossec.conf." \
        || fail "Expected <auth><disabled>no</disabled>."
    [[ "$use_password" == "yes" ]] \
        && pass "Shared-password authentication is enabled." \
        || fail "Expected <auth><use_password>yes</use_password>."
    if [[ "$enrollment_port" =~ ^[0-9]+$ ]] &&
        ((enrollment_port >= 1 && enrollment_port <= 65535)); then
        pass "Enrollment port in ossec.conf is valid: $enrollment_port."
    else
        fail "Enrollment port is missing or invalid."
        enrollment_port="1515"
    fi
fi

if [[ -L "$password_file" ]]; then
    fail "Password file must not be a symbolic link: $password_file"
elif [[ ! -f "$password_file" ]]; then
    fail "Password file does not exist: $password_file"
else
    read -r owner group mode < <(stat -c '%U %G %a' "$password_file")
    [[ "$owner" == "root" ]] \
        && pass "Password file owner is root." \
        || fail "Password file owner is $owner; expected root."
    [[ "$group" == "wazuh" ]] \
        && pass "Password file group is wazuh." \
        || fail "Password file group is $group; expected wazuh."
    [[ "$mode" == "640" ]] \
        && pass "Password file mode is 640." \
        || fail "Password file mode is $mode; expected 640."

    logical_lines="$(awk 'END { print NR }' "$password_file")"
    if [[ "$logical_lines" == "1" ]]; then
        pass "Password file contains exactly one logical line."
    else
        fail "Password file must contain exactly one logical line."
    fi

    password="$(head -n 1 "$password_file")"
    trimmed="$(printf '%s' "$password" |
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [[ -n "$password" && "$password" == "$trimmed" &&
        "$password" != *$'\r'* ]]; then
        pass "Password has a non-empty, GPO-compatible format."
    else
        fail "Password is empty or contains leading/trailing whitespace or CR."
    fi
    if ((${#password} < 16)); then
        warn "Enrollment password is shorter than the recommended 16 characters."
    fi
    unset password trimmed
fi

if [[ -n "$expected_password_file" ]]; then
    if [[ ! -f "$expected_password_file" ]]; then
        fail "Expected-password file does not exist: $expected_password_file"
    elif cmp -s -- "$password_file" "$expected_password_file"; then
        pass "Expected-password file matches manager authd.pass."
    else
        fail "Expected-password file does not match manager authd.pass."
    fi
fi

if systemctl is-active --quiet wazuh-manager; then
    pass "wazuh-manager.service is active."
else
    fail "wazuh-manager.service is not active."
fi

if pgrep -x wazuh-authd >/dev/null; then
    pass "wazuh-authd process is running."
else
    fail "wazuh-authd process is not running."
fi

if command -v ss >/dev/null 2>&1 &&
    ss -H -ltn | awk -v port=":${enrollment_port:-1515}" '
        $4 ~ port "$" { found = 1 }
        END { exit !found }
    '; then
    pass "Enrollment listener is active on TCP ${enrollment_port:-1515}."
else
    fail "Enrollment listener is not active on TCP ${enrollment_port:-1515}."
fi

if /var/ossec/bin/wazuh-authd -t >/dev/null 2>&1; then
    pass "wazuh-authd accepts the current configuration."
else
    fail "wazuh-authd configuration test failed."
fi

printf 'SUMMARY: failures=%d warnings=%d\n' "$failures" "$warnings"
((failures == 0))
