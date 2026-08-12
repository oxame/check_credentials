#!/usr/bin/env bash
#
# check_credentials.sh
# Vérifie des credentials de supervision SNMP, API HTTP(S) et Veeam VBR REST API.
#
# Codes de sortie : 0 = tout valide, 1 = au moins un échec, 2 = erreur de configuration.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/resources.csv}"
SECRETS_FILE="${SECRETS_FILE:-${SCRIPT_DIR}/secrets.env}"
GLOBAL_TIMEOUT="${GLOBAL_TIMEOUT:-10}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-5}"
CURL_MAX_TIME="${CURL_MAX_TIME:-10}"
SNMP_TIMEOUT="${SNMP_TIMEOUT:-2}"
SNMP_RETRIES="${SNMP_RETRIES:-0}"
SNMP_TEST_OID="${SNMP_TEST_OID:-1.3.6.1.2.1.1.5}"
VEEAM_API_VERSION_DEFAULT="${VEEAM_API_VERSION_DEFAULT:-1.3-rev1}"

FILTER_RESOURCE=""
FILTER_PROTOCOL=""
VERBOSE=0
VALID_COUNT=0
INVALID_COUNT=0
TESTED_COUNT=0
SKIPPED_COUNT=0

if [[ -t 1 && "${NO_COLOR:-0}" != "1" ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; RESET=""
fi

TMP_BASE="${XDG_RUNTIME_DIR:-/tmp}"
RUNTIME_DIR=""
cleanup() { [[ -n "${RUNTIME_DIR:-}" && -d "$RUNTIME_DIR" ]] && rm -rf -- "$RUNTIME_DIR"; }
trap cleanup EXIT HUP INT TERM

usage() {
    cat <<'EOF'
Usage:
  ./check_credentials.sh
  ./check_credentials.sh --resource NOM
  ./check_credentials.sh --protocol snmp
  ./check_credentials.sh --protocol api
  ./check_credentials.sh --verbose

Options:
  --resource NOM       Tester uniquement la ressource NOM.
  --protocol PROTO     Filtrer sur snmp ou api.
  --verbose            Diagnostics supplémentaires sans exposer les secrets.
  --config FICHIER     Fichier resources.csv alternatif.
  --secrets FICHIER    Fichier secrets.env alternatif.
  -h, --help           Aide.

Variables facultatives : GLOBAL_TIMEOUT, CURL_CONNECT_TIMEOUT, CURL_MAX_TIME,
SNMP_TIMEOUT, SNMP_RETRIES, SNMP_TEST_OID, VEEAM_API_VERSION_DEFAULT, NO_COLOR=1.
EOF
}

log_verbose() { (( VERBOSE )) && printf '%s[DEBUG]%s %s\n' "$BLUE" "$RESET" "$*" >&2 || true; }
die() { printf '%sERREUR:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 2; }
lower() { printf '%s' "${1,,}"; }
trim_cr() { printf '%s' "${1%$'\r'}"; }
is_valid_var_name() { [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; }

get_secret() {
    local ref="${1:-}"
    [[ -n "$ref" ]] || return 1
    is_valid_var_name "$ref" || return 2
    [[ -v "$ref" ]] || return 2
    printf '%s' "${!ref}"
}

require_secret() {
    local ref="$1" description="$2" value
    if ! value="$(get_secret "$ref")"; then
        printf '%s' "Secret absent ou référence invalide : ${description} (${ref})"
        return 1
    fi
    [[ -n "$value" ]] || { printf '%s' "Secret vide : ${description} (${ref})"; return 1; }
    printf '%s' "$value"
}

safe_single_line() { [[ "$1" != *$'\n'* && "$1" != *$'\r'* ]]; }
curl_config_escape() {
    local value="$1"
    safe_single_line "$value" || return 1
    value="${value//\\/\\\\}"; value="${value//\"/\\\"}"
    printf '%s' "$value"
}

create_runtime_dir() {
    umask 077
    RUNTIME_DIR="$(mktemp -d "${TMP_BASE%/}/check_credentials.XXXXXXXX")" || die "Impossible de créer le répertoire temporaire."
    chmod 700 "$RUNTIME_DIR" || die "Impossible de protéger le répertoire temporaire."
}

check_file_permissions() {
    local file="$1" mode group_digit other_digit
    [[ -f "$file" ]] || die "Fichier de secrets introuvable : $file"
    mode="$(stat -c '%a' "$file" 2>/dev/null)" || die "Impossible de lire les permissions de $file"
    group_digit="${mode: -2:1}"; other_digit="${mode: -1}"
    if (( 10#$group_digit != 0 || 10#$other_digit != 0 )); then
        die "Permissions non sûres sur $file (mode $mode). Utiliser : chmod 600 '$file'"
    fi
}

load_secrets() {
    check_file_permissions "$SECRETS_FILE"
    # shellcheck disable=SC1090
    source "$SECRETS_FILE"
}

check_dependencies() {
    local missing=() cmd
    for cmd in curl snmpwalk timeout stat mktemp sed; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if (( ${#missing[@]} )); then
        printf '%sDépendances manquantes :%s\n' "$RED" "$RESET" >&2
        printf '  - %s\n' "${missing[@]}" >&2
        return 1
    fi
}

print_header() {
    printf '%-28s | %-30s | %-10s | %-6s | %s\n' "RESSOURCE" "IP/FQDN" "PROTOCOLE" "PORT" "RÉSULTAT"
    printf '%-28s-+-%-30s-+-%-10s-+-%-6s-+-%s\n' "----------------------------" "------------------------------" "----------" "------" "------------------------------------------"
}

print_result() {
    local name="$1" host="$2" protocol="$3" port="$4" valid="$5" reason="$6" status
    if [[ "$valid" == "1" ]]; then
        status="${GREEN}VALIDE${RESET}"; [[ -n "$reason" ]] && status+=" - $reason"; ((VALID_COUNT++))
    else
        status="${RED}NON VALIDE${RESET}"; [[ -n "$reason" ]] && status+=" - $reason"; ((INVALID_COUNT++))
    fi
    ((TESTED_COUNT++))
    printf '%-28.28s | %-30.30s | %-10.10s | %-6.6s | %b\n' "$name" "$host" "$protocol" "$port" "$status"
}

classify_snmp_error() {
    local output="$1" rc="$2" text="${output,,}"
    if (( rc == 124 )); then printf '%s' "Timeout"
    elif [[ "$text" == *"authentication failure"* || "$text" == *"authenticationfailure"* || "$text" == *"wrong digest"* || "$text" == *"unknown user name"* || "$text" == *"unknown username"* ]]; then printf '%s' "SNMP authentication failure"
    elif [[ "$text" == *"decryption error"* || "$text" == *"decryptionerror"* ]]; then printf '%s' "SNMP privacy/decryption failure"
    elif [[ "$text" == *"timeout: no response"* || "$text" == *"no response from"* ]]; then printf '%s' "Timeout / No SNMP response"
    elif [[ "$text" == *"unknown host"* || "$text" == *"name or service not known"* || "$text" == *"temporary failure in name resolution"* ]]; then printf '%s' "DNS resolution failure"
    elif [[ "$text" == *"network is unreachable"* || "$text" == *"no route to host"* ]]; then printf '%s' "Host unreachable"
    elif [[ "$text" == *"connection refused"* ]]; then printf '%s' "Port closed / Connection refused"
    elif [[ "$text" == *"authorizationerror"* || "$text" == *"authorization error"* || "$text" == *"no access"* ]]; then printf '%s' "SNMP authorization denied"
    else printf 'SNMP request failed (rc=%s)' "$rc"
    fi
}

build_snmp_target() {
    local host="$1" port="$2"
    if [[ -z "$port" || "$port" == "161" ]]; then printf '%s' "$host"; else printf 'udp:%s:%s' "$host" "$port"; fi
}

test_snmp_v1_v2c() {
    local host="$1" port="$2" version="$3" community_ref="$4" community target output rc reason
    if ! community="$(require_secret "$community_ref" "SNMP community")"; then printf '0|%s' "$community"; return; fi
    target="$(build_snmp_target "$host" "$port")"
    output="$(timeout "$GLOBAL_TIMEOUT" snmpwalk -v "$version" -c "$community" -t "$SNMP_TIMEOUT" -r "$SNMP_RETRIES" -Oqv "$target" "$SNMP_TEST_OID" 2>&1)"; rc=$?; community=""
    if (( rc == 0 )) && [[ -n "$output" ]]; then printf '1|SNMP response OK'; return; fi
    reason="$(classify_snmp_error "$output" "$rc")"; log_verbose "SNMP v$version host=$host rc=$rc reason=$reason"; printf '0|%s' "$reason"
}

test_snmp_v3_noauth() {
    local host="$1" port="$2" username_ref="$3" username target output rc reason
    if ! username="$(require_secret "$username_ref" "SNMPv3 username")"; then printf '0|%s' "$username"; return; fi
    target="$(build_snmp_target "$host" "$port")"
    output="$(timeout "$GLOBAL_TIMEOUT" snmpwalk -v3 -u "$username" -l noAuthNoPriv -t "$SNMP_TIMEOUT" -r "$SNMP_RETRIES" -Oqv "$target" "$SNMP_TEST_OID" 2>&1)"; rc=$?
    if (( rc == 0 )) && [[ -n "$output" ]]; then printf '1|SNMPv3 response OK'; return; fi
    reason="$(classify_snmp_error "$output" "$rc")"; printf '0|%s' "$reason"
}

test_snmp_v3_auth() {
    local host="$1" port="$2" username_ref="$3" auth_proto="$4" auth_pass_ref="$5" username auth_pass target output rc reason
    if ! username="$(require_secret "$username_ref" "SNMPv3 username")"; then printf '0|%s' "$username"; return; fi
    if ! auth_pass="$(require_secret "$auth_pass_ref" "SNMPv3 authentication password")"; then printf '0|%s' "$auth_pass"; return; fi
    [[ -n "$auth_proto" ]] || { printf '0|SNMPv3 authentication protocol missing'; return; }
    target="$(build_snmp_target "$host" "$port")"
    output="$(timeout "$GLOBAL_TIMEOUT" snmpwalk -v3 -u "$username" -l authNoPriv -a "$auth_proto" -A "$auth_pass" -t "$SNMP_TIMEOUT" -r "$SNMP_RETRIES" -Oqv "$target" "$SNMP_TEST_OID" 2>&1)"; rc=$?; auth_pass=""
    if (( rc == 0 )) && [[ -n "$output" ]]; then printf '1|SNMPv3 response OK'; return; fi
    reason="$(classify_snmp_error "$output" "$rc")"; printf '0|%s' "$reason"
}

test_snmp_v3_authpriv() {
    local host="$1" port="$2" username_ref="$3" auth_proto="$4" auth_pass_ref="$5" priv_proto="$6" priv_pass_ref="$7"
    local username auth_pass priv_pass target output rc reason
    if ! username="$(require_secret "$username_ref" "SNMPv3 username")"; then printf '0|%s' "$username"; return; fi
    if ! auth_pass="$(require_secret "$auth_pass_ref" "SNMPv3 authentication password")"; then printf '0|%s' "$auth_pass"; return; fi
    if ! priv_pass="$(require_secret "$priv_pass_ref" "SNMPv3 privacy password")"; then printf '0|%s' "$priv_pass"; return; fi
    [[ -n "$auth_proto" ]] || { printf '0|SNMPv3 authentication protocol missing'; return; }
    [[ -n "$priv_proto" ]] || { printf '0|SNMPv3 privacy protocol missing'; return; }
    target="$(build_snmp_target "$host" "$port")"
    output="$(timeout "$GLOBAL_TIMEOUT" snmpwalk -v3 -u "$username" -l authPriv -a "$auth_proto" -A "$auth_pass" -x "$priv_proto" -X "$priv_pass" -t "$SNMP_TIMEOUT" -r "$SNMP_RETRIES" -Oqv "$target" "$SNMP_TEST_OID" 2>&1)"; rc=$?; auth_pass=""; priv_pass=""
    if (( rc == 0 )) && [[ -n "$output" ]]; then printf '1|SNMPv3 response OK'; return; fi
    reason="$(classify_snmp_error "$output" "$rc")"; printf '0|%s' "$reason"
}

test_snmp() {
    local host="$1" port="$2" version="$3" community_ref="$4" username_ref="$5" sec_level="$6" auth_proto="$7" auth_pass_ref="$8" priv_proto="$9" priv_pass_ref="${10}"
    case "${version,,}" in
        1) test_snmp_v1_v2c "$host" "$port" 1 "$community_ref" ;;
        2|2c) test_snmp_v1_v2c "$host" "$port" 2c "$community_ref" ;;
        3) case "${sec_level,,}" in
            noauthnopriv) test_snmp_v3_noauth "$host" "$port" "$username_ref" ;;
            authnopriv) test_snmp_v3_auth "$host" "$port" "$username_ref" "$auth_proto" "$auth_pass_ref" ;;
            authpriv) test_snmp_v3_authpriv "$host" "$port" "$username_ref" "$auth_proto" "$auth_pass_ref" "$priv_proto" "$priv_pass_ref" ;;
            *) printf '0|Unsupported SNMPv3 security level: %s' "$sec_level" ;;
        esac ;;
        *) printf '0|Unsupported SNMP version: %s' "$version" ;;
    esac
}

classify_curl_error() {
    case "$1" in
        5) printf '%s' "Proxy resolution failure" ;; 6) printf '%s' "DNS resolution failure" ;;
        7) printf '%s' "Port closed / connection refused" ;; 28|124) printf '%s' "Timeout" ;;
        35) printf '%s' "TLS handshake failure" ;; 47) printf '%s' "Too many redirects" ;;
        52) printf '%s' "Empty response from server" ;; 56) printf '%s' "Network receive failure" ;;
        60) printf '%s' "TLS certificate validation failure" ;; *) printf 'Network/curl error (rc=%s)' "$1" ;;
    esac
}

build_url() {
    local host="$1" protocol="$2" port="$3" endpoint="$4"
    if [[ "$endpoint" =~ ^https?:// ]]; then printf '%s' "$endpoint"; return; fi
    [[ -n "$endpoint" ]] || endpoint="/"; [[ "$endpoint" == /* ]] || endpoint="/$endpoint"
    printf '%s://%s:%s%s' "$protocol" "$host" "$port" "$endpoint"
}

write_curl_config() {
    local file="$1" url="$2" method="$3" auth_type="$4" username="$5" password="$6" token="$7" api_key_header="$8" api_key="$9" verify_tls="${10}" escaped
    umask 077; : > "$file" || return 1; chmod 600 "$file" || return 1
    {
        escaped="$(curl_config_escape "$url")" || return 1; printf 'url = "%s"\n' "$escaped"
        escaped="$(curl_config_escape "$method")" || return 1; printf 'request = "%s"\n' "$escaped"
        printf 'silent\nshow-error\noutput = "/dev/null"\nwrite-out = "%%{http_code}"\n'
        printf 'connect-timeout = "%s"\nmax-time = "%s"\n' "$CURL_CONNECT_TIMEOUT" "$CURL_MAX_TIME"
        [[ "$(lower "$verify_tls")" =~ ^(false|no|0)$ ]] && printf 'insecure\n'
        case "$(lower "$auth_type")" in
            none|"") ;;
            basic) escaped="$(curl_config_escape "${username}:${password}")" || return 1; printf 'user = "%s"\nbasic\n' "$escaped" ;;
            bearer) escaped="$(curl_config_escape "Authorization: Bearer ${token}")" || return 1; printf 'header = "%s"\n' "$escaped" ;;
            apikey|api_key) escaped="$(curl_config_escape "${api_key_header}: ${api_key}")" || return 1; printf 'header = "%s"\n' "$escaped" ;;
            *) return 1 ;;
        esac
    } >> "$file"
}

test_api() {
    local host="$1" scheme="$2" port="$3" auth_type="$4" username_ref="$5" password_ref="$6" endpoint="$7" token_ref="$8" api_key_header="$9" api_key_ref="${10}" method="${11}" verify_tls="${12}"
    local username="" password="" token="" api_key="" url cfg http_code rc
    auth_type="$(lower "$auth_type")"; method="${method:-GET}"; verify_tls="${verify_tls:-true}"
    case "$auth_type" in
        none|"") ;;
        basic) username="$(require_secret "$username_ref" "API username")" || { printf '0|%s' "$username"; return; }; password="$(require_secret "$password_ref" "API password")" || { printf '0|%s' "$password"; return; } ;;
        bearer) token="$(require_secret "$token_ref" "Bearer token")" || { printf '0|%s' "$token"; return; } ;;
        apikey|api_key) [[ -n "$api_key_header" ]] || { printf '0|API key header missing'; return; }; api_key="$(require_secret "$api_key_ref" "API key")" || { printf '0|%s' "$api_key"; return; } ;;
        *) printf '0|Unsupported API authentication type'; return ;;
    esac
    url="$(build_url "$host" "$scheme" "$port" "$endpoint")"; cfg="${RUNTIME_DIR}/curl_${BASHPID}_${RANDOM}.conf"
    write_curl_config "$cfg" "$url" "$method" "$auth_type" "$username" "$password" "$token" "$api_key_header" "$api_key" "$verify_tls" || { rm -f -- "$cfg"; printf '0|Unable to build secure curl configuration'; return; }
    http_code="$(timeout "$GLOBAL_TIMEOUT" curl --disable --config "$cfg" 2>/dev/null)"; rc=$?; rm -f -- "$cfg"; password=""; token=""; api_key=""
    (( rc == 0 )) || { printf '0|%s' "$(classify_curl_error "$rc")"; return; }
    case "$http_code" in
        2??|3??) printf '1|HTTP %s' "$http_code" ;; 401) printf '0|HTTP 401 - Authentication failed' ;;
        403) printf '0|HTTP 403 - Forbidden / authorization denied' ;; 404) printf '0|HTTP 404 - Endpoint not found' ;;
        405) printf '0|HTTP 405 - HTTP method not allowed' ;; 408) printf '0|HTTP 408 - Request timeout' ;;
        429) printf '0|HTTP 429 - Rate limited' ;; 5??) printf '0|HTTP %s - Server error' "$http_code" ;;
        000|"") printf '0|No HTTP response' ;; *) printf '0|HTTP %s' "$http_code" ;;
    esac
}

# Veeam Backup & Replication REST API :
# 1) POST /api/oauth2/token (OAuth2 password grant)
# 2) GET /api/v1/serverInfo avec le Bearer token obtenu.
#
# Le username et le password sont placés dans des fichiers temporaires en 600
# puis envoyés avec data-urlencode name@file. Cela reproduit le comportement du
# curl manuel validé pour les comptes AD DOMAIN\\user, sans exposer les secrets
# dans la ligne de commande du processus curl.
test_veeam() {
    local host="$1" port="$2" username_ref="$3" password_ref="$4" verify_tls="$5" api_version="$6"
    local username password token_url server_url auth_cfg verify_cfg user_file pass_file
    local auth_response auth_http auth_rc access_token verify_http verify_rc escaped

    username="$(require_secret "$username_ref" "Veeam username")" || { printf '0|%s' "$username"; return; }
    password="$(require_secret "$password_ref" "Veeam password")" || { printf '0|%s' "$password"; return; }
    api_version="${api_version:-$VEEAM_API_VERSION_DEFAULT}"; verify_tls="${verify_tls:-true}"
    token_url="https://${host}:${port}/api/oauth2/token"; server_url="https://${host}:${port}/api/v1/serverInfo"
    auth_cfg="${RUNTIME_DIR}/veeam_auth_${BASHPID}_${RANDOM}.conf"
    verify_cfg="${RUNTIME_DIR}/veeam_verify_${BASHPID}_${RANDOM}.conf"
    user_file="${RUNTIME_DIR}/veeam_user_${BASHPID}_${RANDOM}.secret"
    pass_file="${RUNTIME_DIR}/veeam_pass_${BASHPID}_${RANDOM}.secret"

    umask 077
    printf '%s' "$username" > "$user_file" || { printf '0|Unable to create Veeam username temporary file'; return; }
    printf '%s' "$password" > "$pass_file" || { rm -f -- "$user_file"; printf '0|Unable to create Veeam password temporary file'; return; }
    chmod 600 "$user_file" "$pass_file"

    : > "$auth_cfg" || { rm -f -- "$user_file" "$pass_file"; printf '0|Unable to create Veeam curl configuration'; return; }
    chmod 600 "$auth_cfg"
    {
        escaped="$(curl_config_escape "$token_url")" || return; printf 'url = "%s"\nrequest = "POST"\n' "$escaped"
        printf 'silent\nshow-error\nconnect-timeout = "%s"\nmax-time = "%s"\n' "$CURL_CONNECT_TIMEOUT" "$CURL_MAX_TIME"
        printf 'header = "Content-Type: application/x-www-form-urlencoded"\n'
        escaped="$(curl_config_escape "x-api-version: ${api_version}")" || return; printf 'header = "%s"\n' "$escaped"
        printf 'data-urlencode = "grant_type=password"\n'
        printf 'data-urlencode = "username@%s"\n' "$user_file"
        printf 'data-urlencode = "password@%s"\n' "$pass_file"
        printf 'write-out = "\\n%%{http_code}"\n'
        [[ "$(lower "$verify_tls")" =~ ^(false|no|0)$ ]] && printf 'insecure\n'
    } >> "$auth_cfg"

    username=""; password=""
    log_verbose "Veeam auth host=$host port=$port api_version=$api_version"
    auth_response="$(timeout "$GLOBAL_TIMEOUT" curl --disable --config "$auth_cfg" 2>/dev/null)"; auth_rc=$?
    rm -f -- "$auth_cfg" "$user_file" "$pass_file"
    (( auth_rc == 0 )) || { printf '0|%s' "$(classify_curl_error "$auth_rc")"; return; }

    auth_http="${auth_response##*$'\n'}"; auth_response="${auth_response%$'\n'*}"
    case "$auth_http" in
        200) ;;
        400) printf '0|Veeam authentication request rejected (HTTP 400)'; return ;;
        401) printf '0|Veeam authentication failed (HTTP 401)'; return ;;
        403) printf '0|Veeam authentication forbidden (HTTP 403)'; return ;;
        404) printf '0|Veeam OAuth endpoint not found (HTTP 404)'; return ;;
        5??) printf '0|Veeam server error (HTTP %s)' "$auth_http"; return ;;
        *) printf '0|Veeam authentication failed (HTTP %s)' "${auth_http:-000}"; return ;;
    esac

    access_token="$(printf '%s' "$auth_response" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"; auth_response=""
    [[ -n "$access_token" ]] || { printf '0|Veeam authentication succeeded but access_token is missing'; return; }

    umask 077; : > "$verify_cfg" || { access_token=""; printf '0|Unable to create Veeam verification configuration'; return; }; chmod 600 "$verify_cfg"
    {
        escaped="$(curl_config_escape "$server_url")" || return; printf 'url = "%s"\nrequest = "GET"\n' "$escaped"
        printf 'silent\nshow-error\noutput = "/dev/null"\nwrite-out = "%%{http_code}"\n'
        printf 'connect-timeout = "%s"\nmax-time = "%s"\n' "$CURL_CONNECT_TIMEOUT" "$CURL_MAX_TIME"
        escaped="$(curl_config_escape "Authorization: Bearer ${access_token}")" || return; printf 'header = "%s"\n' "$escaped"
        escaped="$(curl_config_escape "x-api-version: ${api_version}")" || return; printf 'header = "%s"\n' "$escaped"
        [[ "$(lower "$verify_tls")" =~ ^(false|no|0)$ ]] && printf 'insecure\n'
    } >> "$verify_cfg"

    verify_http="$(timeout "$GLOBAL_TIMEOUT" curl --disable --config "$verify_cfg" 2>/dev/null)"; verify_rc=$?; rm -f -- "$verify_cfg"; access_token=""
    (( verify_rc == 0 )) || { printf '0|%s' "$(classify_curl_error "$verify_rc")"; return; }
    case "$verify_http" in
        200) printf '1|Veeam authentication OK (HTTP 200)' ;;
        401) printf '0|Veeam token rejected (HTTP 401)' ;;
        403) printf '0|Veeam authenticated but access to serverInfo is forbidden (HTTP 403)' ;;
        404) printf '0|Veeam serverInfo endpoint not found (HTTP 404)' ;;
        5??) printf '0|Veeam server error (HTTP %s)' "$verify_http" ;;
        *) printf '0|Veeam verification failed (HTTP %s)' "${verify_http:-000}" ;;
    esac
}

parse_args() {
    while (( $# > 0 )); do
        case "$1" in
            --resource) [[ $# -ge 2 ]] || die "--resource nécessite une valeur."; FILTER_RESOURCE="$2"; shift 2 ;;
            --protocol) [[ $# -ge 2 ]] || die "--protocol nécessite une valeur."; FILTER_PROTOCOL="$(lower "$2")"; [[ "$FILTER_PROTOCOL" =~ ^(snmp|api)$ ]] || die "--protocol doit être 'snmp' ou 'api'."; shift 2 ;;
            --verbose) VERBOSE=1; shift ;;
            --config) [[ $# -ge 2 ]] || die "--config nécessite un fichier."; CONFIG_FILE="$2"; shift 2 ;;
            --secrets) [[ $# -ge 2 ]] || die "--secrets nécessite un fichier."; SECRETS_FILE="$2"; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            *) die "Option inconnue : $1" ;;
        esac
    done
}

process_resource() {
    local name="$1" host="$2" protocol="$3" port="$4" auth_type="$5" username_ref="$6" password_ref="$7" community_ref="$8" snmp_version="$9"
    local snmp_sec_level="${10}" snmp_auth_proto="${11}" snmp_auth_pass_ref="${12}" snmp_priv_proto="${13}" snmp_priv_pass_ref="${14}"
    local endpoint="${15}" token_ref="${16}" api_key_header="${17}" api_key_ref="${18}" http_method="${19}" verify_tls="${20}" api_version="${21:-}"
    local result valid reason displayed_protocol
    protocol="$(lower "$protocol")"; auth_type="$(lower "$auth_type")"

    if [[ -n "$FILTER_RESOURCE" && "$name" != "$FILTER_RESOURCE" ]]; then ((SKIPPED_COUNT++)); return; fi
    if [[ -n "$FILTER_PROTOCOL" ]]; then
        case "$FILTER_PROTOCOL" in
            snmp) [[ "$protocol" == snmp ]] || { ((SKIPPED_COUNT++)); return; } ;;
            api) [[ "$protocol" =~ ^(http|https|api)$ ]] || { ((SKIPPED_COUNT++)); return; } ;;
        esac
    fi
    if [[ -z "$name" || -z "$host" || -z "$protocol" || -z "$port" ]]; then print_result "${name:-UNKNOWN}" "${host:-UNKNOWN}" "${protocol:-UNKNOWN}" "${port:-?}" 0 "Invalid resource configuration"; return; fi

    case "$protocol" in
        snmp)
            displayed_protocol="SNMP${snmp_version}"
            result="$(test_snmp "$host" "$port" "$snmp_version" "$community_ref" "$username_ref" "$snmp_sec_level" "$snmp_auth_proto" "$snmp_auth_pass_ref" "$snmp_priv_proto" "$snmp_priv_pass_ref")" ;;
        http|https|api)
            if [[ "$auth_type" == "veeam" ]]; then
                displayed_protocol="VEEAM"
                result="$(test_veeam "$host" "$port" "$username_ref" "$password_ref" "$verify_tls" "$api_version")"
            else
                [[ "$protocol" == api ]] && protocol="https"; displayed_protocol="${protocol^^}"
                result="$(test_api "$host" "$protocol" "$port" "$auth_type" "$username_ref" "$password_ref" "$endpoint" "$token_ref" "$api_key_header" "$api_key_ref" "$http_method" "$verify_tls")"
            fi ;;
        *) print_result "$name" "$host" "$protocol" "$port" 0 "Unsupported protocol"; return ;;
    esac
    valid="${result%%|*}"; reason="${result#*|}"
    print_result "$name" "$host" "$displayed_protocol" "$port" "$valid" "$reason"
}

process_csv() {
    [[ -f "$CONFIG_FILE" ]] || die "Fichier de configuration introuvable : $CONFIG_FILE"
    local line_number=0 found_resource=0
    while IFS=',' read -r name host protocol port auth_type username_ref password_ref community_ref snmp_version snmp_sec_level snmp_auth_proto snmp_auth_pass_ref snmp_priv_proto snmp_priv_pass_ref endpoint token_ref api_key_header api_key_ref http_method verify_tls api_version; do
        ((line_number++)); verify_tls="$(trim_cr "${verify_tls:-}")"; api_version="$(trim_cr "${api_version:-}")"
        [[ -n "${name//[[:space:]]/}" ]] || continue; [[ "$name" == \#* ]] && continue
        if (( line_number == 1 )) && [[ "$(lower "$name")" == name ]]; then continue; fi
        found_resource=1
        process_resource "$name" "$host" "$protocol" "$port" "$auth_type" "$username_ref" "$password_ref" "$community_ref" "$snmp_version" "$snmp_sec_level" "$snmp_auth_proto" "$snmp_auth_pass_ref" "$snmp_priv_proto" "$snmp_priv_pass_ref" "$endpoint" "$token_ref" "$api_key_header" "$api_key_ref" "$http_method" "$verify_tls" "$api_version"
    done < "$CONFIG_FILE"
    (( found_resource )) || die "Aucune ressource dans $CONFIG_FILE"
}

print_summary() {
    printf '\n%s---%s\n\n%sRésumé des tests%s\n\n' "$BOLD" "$RESET" "$BOLD" "$RESET"
    printf 'Ressources testées     : %d\n' "$TESTED_COUNT"
    printf 'Ressources valides     : %b%d%b\n' "$GREEN" "$VALID_COUNT" "$RESET"
    printf 'Ressources non valides : %b%d%b\n' "$RED" "$INVALID_COUNT" "$RESET"
    (( VERBOSE && SKIPPED_COUNT > 0 )) && printf 'Ressources ignorées    : %d\n' "$SKIPPED_COUNT"
}

main() {
    parse_args "$@"; check_dependencies || exit 2; load_secrets; create_runtime_dir
    printf '%sVérification des credentials de supervision%s\nConfiguration : %s\n\n' "$BOLD" "$RESET" "$CONFIG_FILE"
    print_header; process_csv; print_summary
    if (( TESTED_COUNT == 0 )); then printf '\n%sAucune ressource ne correspond aux filtres.%s\n' "$YELLOW" "$RESET"; exit 2; fi
    (( INVALID_COUNT > 0 )) && exit 1
    exit 0
}

main "$@"