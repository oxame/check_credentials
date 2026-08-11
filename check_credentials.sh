#!/usr/bin/env bash
#
# check_credentials.sh
#
# Vérification de credentials de supervision :
#   - SNMP v1 / v2c
#   - SNMPv3 : noAuthNoPriv / authNoPriv / authPriv
#   - API HTTP/HTTPS : Basic / Bearer / API Key / none
#
# Les ressources sont décrites dans resources.csv.
# Les secrets sont stockés dans secrets.env, avec permissions 600.
#
# Codes de sortie :
#   0 = tous les tests exécutés sont valides
#   1 = au moins un test est non valide
#   2 = erreur de configuration / dépendance / argument
#

set -uo pipefail

###############################################################################
# Configuration générale
###############################################################################

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/resources.csv}"
SECRETS_FILE="${SECRETS_FILE:-${SCRIPT_DIR}/secrets.env}"

GLOBAL_TIMEOUT="${GLOBAL_TIMEOUT:-10}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-5}"
CURL_MAX_TIME="${CURL_MAX_TIME:-10}"

SNMP_TIMEOUT="${SNMP_TIMEOUT:-2}"
SNMP_RETRIES="${SNMP_RETRIES:-0}"

# Même OID que dans les scripts SNMP validés : sysName.
SNMP_TEST_OID="${SNMP_TEST_OID:-1.3.6.1.2.1.1.5}"

FILTER_RESOURCE=""
FILTER_PROTOCOL=""
VERBOSE=0

VALID_COUNT=0
INVALID_COUNT=0
TESTED_COUNT=0
SKIPPED_COUNT=0

###############################################################################
# Couleurs ANSI
###############################################################################

if [[ -t 1 && "${NO_COLOR:-0}" != "1" ]]; then
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    BOLD=""
    RESET=""
fi

###############################################################################
# Répertoire temporaire protégé
###############################################################################

TMP_BASE="${XDG_RUNTIME_DIR:-/tmp}"
RUNTIME_DIR=""

cleanup() {
    if [[ -n "${RUNTIME_DIR:-}" && -d "$RUNTIME_DIR" ]]; then
        rm -rf -- "$RUNTIME_DIR"
    fi
}

trap cleanup EXIT HUP INT TERM

###############################################################################
# Fonctions utilitaires
###############################################################################

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
  --protocol PROTO     Filtrer sur "snmp" ou "api".
  --verbose            Afficher davantage de diagnostics, sans secrets.
  --config FICHIER     Utiliser un autre fichier resources.csv.
  --secrets FICHIER    Utiliser un autre fichier secrets.env.
  -h, --help           Afficher cette aide.

Variables d'environnement facultatives :
  GLOBAL_TIMEOUT
  CURL_CONNECT_TIMEOUT
  CURL_MAX_TIME
  SNMP_TIMEOUT
  SNMP_RETRIES
  SNMP_TEST_OID
  NO_COLOR=1
EOF
}

log_verbose() {
    if (( VERBOSE )); then
        printf '%s[DEBUG]%s %s\n' "$BLUE" "$RESET" "$*" >&2
    fi
}

die() {
    printf '%sERREUR:%s %s\n' "$RED" "$RESET" "$*" >&2
    exit 2
}

trim_cr() {
    local value="$1"
    printf '%s' "${value%$'\r'}"
}

lower() {
    printf '%s' "${1,,}"
}

is_valid_var_name() {
    [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
}

get_secret() {
    local ref="${1:-}"

    [[ -n "$ref" ]] || return 1
    is_valid_var_name "$ref" || return 2
    [[ -v "$ref" ]] || return 2

    printf '%s' "${!ref}"
}

require_secret() {
    local ref="$1"
    local description="$2"
    local value

    if ! value="$(get_secret "$ref")"; then
        printf '%s' "Secret absent ou référence invalide : ${description} (${ref})"
        return 1
    fi

    if [[ -z "$value" ]]; then
        printf '%s' "Secret vide : ${description} (${ref})"
        return 1
    fi

    printf '%s' "$value"
}

safe_single_line() {
    [[ "$1" != *$'\n'* && "$1" != *$'\r'* ]]
}

curl_config_escape() {
    local value="$1"

    safe_single_line "$value" || return 1
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s' "$value"
}

create_runtime_dir() {
    umask 077
    RUNTIME_DIR="$(mktemp -d "${TMP_BASE%/}/check_credentials.XXXXXXXX")" \
        || die "Impossible de créer le répertoire temporaire."
    chmod 700 "$RUNTIME_DIR" \
        || die "Impossible de protéger le répertoire temporaire."
}

###############################################################################
# Validation des fichiers et dépendances
###############################################################################

check_file_permissions() {
    local file="$1"
    local mode
    local group_digit
    local other_digit

    [[ -f "$file" ]] || die "Fichier de secrets introuvable : $file"

    mode="$(stat -c '%a' "$file" 2>/dev/null)" \
        || die "Impossible de lire les permissions de $file"

    group_digit="${mode: -2:1}"
    other_digit="${mode: -1}"

    if (( 10#$group_digit != 0 || 10#$other_digit != 0 )); then
        die "Permissions non sûres sur $file (mode $mode). Utiliser : chmod 600 '$file'"
    fi

    log_verbose "Permissions du fichier de secrets acceptées : $mode"
}

load_secrets() {
    check_file_permissions "$SECRETS_FILE"
    # shellcheck disable=SC1090
    source "$SECRETS_FILE"
    log_verbose "Fichier de secrets chargé."
}

check_dependencies() {
    local missing=()
    local cmd

    for cmd in curl snmpwalk timeout stat mktemp; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        printf '%sDépendances manquantes :%s\n' "$RED" "$RESET" >&2
        for cmd in "${missing[@]}"; do
            printf '  - %s\n' "$cmd" >&2
        done
        return 1
    fi

    return 0
}

###############################################################################
# Affichage des résultats
###############################################################################

print_header() {
    printf '%-28s | %-30s | %-10s | %-6s | %s\n' \
        "RESSOURCE" "IP/FQDN" "PROTOCOLE" "PORT" "RÉSULTAT"

    printf '%-28s-+-%-30s-+-%-10s-+-%-6s-+-%s\n' \
        "----------------------------" \
        "------------------------------" \
        "----------" \
        "------" \
        "------------------------------------------"
}

print_result() {
    local name="$1"
    local host="$2"
    local protocol="$3"
    local port="$4"
    local valid="$5"
    local reason="$6"
    local status

    if [[ "$valid" == "1" ]]; then
        status="${GREEN}VALIDE${RESET}"
        [[ -n "$reason" ]] && status+=" - $reason"
        ((VALID_COUNT++))
    else
        status="${RED}NON VALIDE${RESET}"
        [[ -n "$reason" ]] && status+=" - $reason"
        ((INVALID_COUNT++))
    fi

    ((TESTED_COUNT++))

    printf '%-28.28s | %-30.30s | %-10.10s | %-6.6s | %b\n' \
        "$name" "$host" "$protocol" "$port" "$status"
}

###############################################################################
# Gestion SNMP
###############################################################################

build_snmp_target() {
    local host="$1"
    local port="$2"

    if [[ -z "$port" || "$port" == "161" ]]; then
        printf '%s' "$host"
    else
        printf 'udp:%s:%s' "$host" "$port"
    fi
}

classify_snmp_error() {
    local output="$1"
    local rc="$2"
    local text="${output,,}"

    if (( rc == 124 )); then
        printf '%s' "Timeout"
    elif [[ "$text" == *"timeout: no response"* ]] ||
         [[ "$text" == *"no response from"* ]]; then
        printf '%s' "Timeout / no SNMP response"
    elif [[ "$text" == *"authentication failure"* ]] ||
         [[ "$text" == *"authenticationfailure"* ]] ||
         [[ "$text" == *"wrong digest"* ]] ||
         [[ "$text" == *"unknown user name"* ]] ||
         [[ "$text" == *"unknown username"* ]]; then
        printf '%s' "SNMP authentication failure"
    elif [[ "$text" == *"decryption error"* ]] ||
         [[ "$text" == *"decryptionerror"* ]]; then
        printf '%s' "SNMP privacy/decryption failure"
    elif [[ "$text" == *"authorizationerror"* ]] ||
         [[ "$text" == *"authorization error"* ]] ||
         [[ "$text" == *"no access"* ]]; then
        printf '%s' "SNMP authorization denied"
    elif [[ "$text" == *"unknown host"* ]] ||
         [[ "$text" == *"name or service not known"* ]] ||
         [[ "$text" == *"temporary failure in name resolution"* ]]; then
        printf '%s' "DNS resolution failure"
    elif [[ "$text" == *"network is unreachable"* ]] ||
         [[ "$text" == *"no route to host"* ]]; then
        printf '%s' "Host unreachable"
    elif [[ "$text" == *"connection refused"* ]]; then
        printf '%s' "Port closed / connection refused"
    else
        printf 'SNMP request failed (rc=%s)' "$rc"
    fi
}

test_snmp_v1_v2c() {
    local host="$1"
    local port="$2"
    local version="$3"
    local community_ref="$4"
    local community
    local target
    local output
    local rc
    local reason

    if ! community="$(require_secret "$community_ref" "community SNMP")"; then
        printf '0|%s' "$community"
        return
    fi

    target="$(build_snmp_target "$host" "$port")"
    log_verbose "SNMP test host=$host port=$port version=$version oid=$SNMP_TEST_OID"

    output="$(
        timeout "$GLOBAL_TIMEOUT" \
        snmpwalk \
            -v "$version" \
            -c "$community" \
            -t "$SNMP_TIMEOUT" \
            -r "$SNMP_RETRIES" \
            -Oqv \
            "$target" \
            "$SNMP_TEST_OID" \
            2>&1
    )"
    rc=$?
    community=""

    if (( rc == 0 )) && [[ -n "$output" ]]; then
        printf '1|SNMP response OK'
        return
    fi

    reason="$(classify_snmp_error "$output" "$rc")"
    log_verbose "SNMP v${version} result host=$host rc=$rc reason=$reason"
    printf '0|%s' "$reason"
}

test_snmp_v3_noauth() {
    local host="$1"
    local port="$2"
    local username_ref="$3"
    local username
    local target
    local output
    local rc
    local reason

    if ! username="$(require_secret "$username_ref" "username SNMPv3")"; then
        printf '0|%s' "$username"
        return
    fi

    target="$(build_snmp_target "$host" "$port")"
    log_verbose "SNMPv3 test host=$host port=$port level=noAuthNoPriv"

    output="$(
        timeout "$GLOBAL_TIMEOUT" \
        snmpwalk \
            -v3 \
            -u "$username" \
            -l noAuthNoPriv \
            -t "$SNMP_TIMEOUT" \
            -r "$SNMP_RETRIES" \
            -Oqv \
            "$target" \
            "$SNMP_TEST_OID" \
            2>&1
    )"
    rc=$?

    if (( rc == 0 )) && [[ -n "$output" ]]; then
        printf '1|SNMPv3 response OK'
        return
    fi

    reason="$(classify_snmp_error "$output" "$rc")"
    log_verbose "SNMPv3 result host=$host level=noAuthNoPriv rc=$rc reason=$reason"
    printf '0|%s' "$reason"
}

test_snmp_v3_auth() {
    local host="$1"
    local port="$2"
    local username_ref="$3"
    local auth_proto="$4"
    local auth_pass_ref="$5"
    local username
    local auth_pass
    local target
    local output
    local rc
    local reason

    if ! username="$(require_secret "$username_ref" "username SNMPv3")"; then
        printf '0|%s' "$username"
        return
    fi

    if ! auth_pass="$(require_secret "$auth_pass_ref" "mot de passe d'authentification SNMPv3")"; then
        printf '0|%s' "$auth_pass"
        return
    fi

    [[ -n "$auth_proto" ]] || {
        printf '0|SNMPv3 authentication protocol missing'
        return
    }

    target="$(build_snmp_target "$host" "$port")"
    log_verbose "SNMPv3 test host=$host port=$port level=authNoPriv auth=$auth_proto"

    output="$(
        timeout "$GLOBAL_TIMEOUT" \
        snmpwalk \
            -v3 \
            -u "$username" \
            -l authNoPriv \
            -a "$auth_proto" \
            -A "$auth_pass" \
            -t "$SNMP_TIMEOUT" \
            -r "$SNMP_RETRIES" \
            -Oqv \
            "$target" \
            "$SNMP_TEST_OID" \
            2>&1
    )"
    rc=$?
    auth_pass=""

    if (( rc == 0 )) && [[ -n "$output" ]]; then
        printf '1|SNMPv3 response OK'
        return
    fi

    reason="$(classify_snmp_error "$output" "$rc")"
    log_verbose "SNMPv3 result host=$host level=authNoPriv rc=$rc reason=$reason"
    printf '0|%s' "$reason"
}

test_snmp_v3_authpriv() {
    local host="$1"
    local port="$2"
    local username_ref="$3"
    local auth_proto="$4"
    local auth_pass_ref="$5"
    local priv_proto="$6"
    local priv_pass_ref="$7"
    local username
    local auth_pass
    local priv_pass
    local target
    local output
    local rc
    local reason

    if ! username="$(require_secret "$username_ref" "username SNMPv3")"; then
        printf '0|%s' "$username"
        return
    fi

    if ! auth_pass="$(require_secret "$auth_pass_ref" "mot de passe d'authentification SNMPv3")"; then
        printf '0|%s' "$auth_pass"
        return
    fi

    if ! priv_pass="$(require_secret "$priv_pass_ref" "mot de passe de chiffrement SNMPv3")"; then
        printf '0|%s' "$priv_pass"
        return
    fi

    [[ -n "$auth_proto" ]] || {
        printf '0|SNMPv3 authentication protocol missing'
        return
    }

    [[ -n "$priv_proto" ]] || {
        printf '0|SNMPv3 privacy protocol missing'
        return
    }

    target="$(build_snmp_target "$host" "$port")"
    log_verbose "SNMPv3 test host=$host port=$port level=authPriv auth=$auth_proto priv=$priv_proto"

    output="$(
        timeout "$GLOBAL_TIMEOUT" \
        snmpwalk \
            -v3 \
            -u "$username" \
            -l authPriv \
            -a "$auth_proto" \
            -A "$auth_pass" \
            -x "$priv_proto" \
            -X "$priv_pass" \
            -t "$SNMP_TIMEOUT" \
            -r "$SNMP_RETRIES" \
            -Oqv \
            "$target" \
            "$SNMP_TEST_OID" \
            2>&1
    )"
    rc=$?
    auth_pass=""
    priv_pass=""

    if (( rc == 0 )) && [[ -n "$output" ]]; then
        printf '1|SNMPv3 response OK'
        return
    fi

    reason="$(classify_snmp_error "$output" "$rc")"
    log_verbose "SNMPv3 result host=$host level=authPriv rc=$rc reason=$reason"
    printf '0|%s' "$reason"
}

test_snmp() {
    local host="$1"
    local port="$2"
    local snmp_version="$3"
    local community_ref="$4"
    local username_ref="$5"
    local sec_level="$6"
    local auth_proto="$7"
    local auth_pass_ref="$8"
    local priv_proto="$9"
    local priv_pass_ref="${10}"

    case "${snmp_version,,}" in
        1)
            test_snmp_v1_v2c "$host" "$port" "1" "$community_ref"
            ;;
        2|2c)
            test_snmp_v1_v2c "$host" "$port" "2c" "$community_ref"
            ;;
        3)
            case "${sec_level,,}" in
                noauthnopriv)
                    test_snmp_v3_noauth "$host" "$port" "$username_ref"
                    ;;
                authnopriv)
                    test_snmp_v3_auth \
                        "$host" "$port" "$username_ref" \
                        "$auth_proto" "$auth_pass_ref"
                    ;;
                authpriv)
                    test_snmp_v3_authpriv \
                        "$host" "$port" "$username_ref" \
                        "$auth_proto" "$auth_pass_ref" \
                        "$priv_proto" "$priv_pass_ref"
                    ;;
                *)
                    printf '0|Unsupported SNMPv3 security level: %s' "$sec_level"
                    ;;
            esac
            ;;
        *)
            printf '0|Unsupported SNMP version: %s' "$snmp_version"
            ;;
    esac
}

###############################################################################
# Gestion HTTP / API
###############################################################################

classify_curl_error() {
    local rc="$1"

    case "$rc" in
        5)  printf '%s' "Proxy resolution failure" ;;
        6)  printf '%s' "DNS resolution failure" ;;
        7)  printf '%s' "Port closed / connection refused" ;;
        28) printf '%s' "Timeout" ;;
        35) printf '%s' "TLS handshake failure" ;;
        47) printf '%s' "Too many redirects" ;;
        52) printf '%s' "Empty response from server" ;;
        56) printf '%s' "Network receive failure" ;;
        60) printf '%s' "TLS certificate validation failure" ;;
        *)  printf 'Network/curl error (rc=%s)' "$rc" ;;
    esac
}

build_url() {
    local host="$1"
    local protocol="$2"
    local port="$3"
    local endpoint="$4"

    if [[ "$endpoint" =~ ^https?:// ]]; then
        printf '%s' "$endpoint"
        return
    fi

    [[ -n "$endpoint" ]] || endpoint="/"
    [[ "$endpoint" == /* ]] || endpoint="/$endpoint"

    printf '%s://%s:%s%s' "$protocol" "$host" "$port" "$endpoint"
}

write_curl_config() {
    local file="$1"
    local url="$2"
    local method="$3"
    local auth_type="$4"
    local username="$5"
    local password="$6"
    local token="$7"
    local api_key_header="$8"
    local api_key="$9"
    local verify_tls="${10}"
    local escaped

    umask 077
    : > "$file" || return 1
    chmod 600 "$file" || return 1

    {
        escaped="$(curl_config_escape "$url")" || return 1
        printf 'url = "%s"\n' "$escaped"

        escaped="$(curl_config_escape "$method")" || return 1
        printf 'request = "%s"\n' "$escaped"

        printf 'silent\n'
        printf 'show-error\n'
        printf 'output = "/dev/null"\n'
        printf 'write-out = "%%{http_code}"\n'
        printf 'connect-timeout = "%s"\n' "$CURL_CONNECT_TIMEOUT"
        printf 'max-time = "%s"\n' "$CURL_MAX_TIME"

        if [[ "$(lower "$verify_tls")" == "false" ||
              "$(lower "$verify_tls")" == "no" ||
              "$verify_tls" == "0" ]]; then
            printf 'insecure\n'
        fi

        case "$(lower "$auth_type")" in
            none|"")
                ;;
            basic)
                escaped="$(curl_config_escape "${username}:${password}")" || return 1
                printf 'user = "%s"\n' "$escaped"
                printf 'basic\n'
                ;;
            bearer)
                escaped="$(curl_config_escape "Authorization: Bearer ${token}")" || return 1
                printf 'header = "%s"\n' "$escaped"
                ;;
            apikey|api_key)
                escaped="$(curl_config_escape "${api_key_header}: ${api_key}")" || return 1
                printf 'header = "%s"\n' "$escaped"
                ;;
            *)
                return 1
                ;;
        esac
    } >> "$file"
}

test_api() {
    local host="$1"
    local scheme="$2"
    local port="$3"
    local auth_type="$4"
    local username_ref="$5"
    local password_ref="$6"
    local endpoint="$7"
    local token_ref="$8"
    local api_key_header="$9"
    local api_key_ref="${10}"
    local method="${11}"
    local verify_tls="${12}"

    local username=""
    local password=""
    local token=""
    local api_key=""
    local url
    local cfg
    local http_code
    local rc

    auth_type="$(lower "$auth_type")"
    method="${method:-GET}"
    verify_tls="${verify_tls:-true}"

    case "$auth_type" in
        none|"")
            ;;
        basic)
            if ! username="$(require_secret "$username_ref" "API username")"; then
                printf '0|%s' "$username"
                return
            fi
            if ! password="$(require_secret "$password_ref" "API password")"; then
                printf '0|%s' "$password"
                return
            fi
            ;;
        bearer)
            if ! token="$(require_secret "$token_ref" "Bearer token")"; then
                printf '0|%s' "$token"
                return
            fi
            ;;
        apikey|api_key)
            [[ -n "$api_key_header" ]] || {
                printf '0|API key header missing'
                return
            }
            if ! api_key="$(require_secret "$api_key_ref" "API key")"; then
                printf '0|%s' "$api_key"
                return
            fi
            ;;
        *)
            printf '0|Unsupported API authentication type'
            return
            ;;
    esac

    url="$(build_url "$host" "$scheme" "$port" "$endpoint")"
    cfg="${RUNTIME_DIR}/curl_${BASHPID}_${RANDOM}.conf"

    if ! write_curl_config \
        "$cfg" "$url" "$method" "$auth_type" "$username" "$password" \
        "$token" "$api_key_header" "$api_key" "$verify_tls"; then
        rm -f -- "$cfg"
        printf '0|Unable to build secure curl configuration'
        return
    fi

    log_verbose \
        "API test host=$host scheme=$scheme port=$port method=$method endpoint=$endpoint auth=$auth_type"

    http_code="$(
        timeout "$GLOBAL_TIMEOUT" \
        curl --disable --config "$cfg" \
        2>/dev/null
    )"
    rc=$?

    rm -f -- "$cfg"

    if (( rc != 0 )); then
        printf '0|%s' "$(classify_curl_error "$rc")"
        return
    fi

    case "$http_code" in
        2??) printf '1|HTTP %s' "$http_code" ;;
        3??) printf '1|HTTP %s' "$http_code" ;;
        401) printf '0|HTTP 401 - Authentication failed' ;;
        403) printf '0|HTTP 403 - Forbidden / authorization denied' ;;
        404) printf '0|HTTP 404 - Endpoint not found' ;;
        405) printf '0|HTTP 405 - HTTP method not allowed' ;;
        408) printf '0|HTTP 408 - Request timeout' ;;
        429) printf '0|HTTP 429 - Rate limited' ;;
        5??) printf '0|HTTP %s - Server error' "$http_code" ;;
        000|"") printf '0|No HTTP response' ;;
        *) printf '0|HTTP %s' "$http_code" ;;
    esac
}

###############################################################################
# Parsing des arguments
###############################################################################

parse_args() {
    while (( $# > 0 )); do
        case "$1" in
            --resource)
                [[ $# -ge 2 ]] || die "--resource nécessite une valeur."
                FILTER_RESOURCE="$2"
                shift 2
                ;;
            --protocol)
                [[ $# -ge 2 ]] || die "--protocol nécessite une valeur."
                FILTER_PROTOCOL="$(lower "$2")"
                case "$FILTER_PROTOCOL" in
                    snmp|api) ;;
                    *) die "--protocol doit être 'snmp' ou 'api'." ;;
                esac
                shift 2
                ;;
            --verbose)
                VERBOSE=1
                shift
                ;;
            --config)
                [[ $# -ge 2 ]] || die "--config nécessite un fichier."
                CONFIG_FILE="$2"
                shift 2
                ;;
            --secrets)
                [[ $# -ge 2 ]] || die "--secrets nécessite un fichier."
                SECRETS_FILE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Option inconnue : $1"
                ;;
        esac
    done
}

###############################################################################
# Traitement d'une ressource
###############################################################################

process_resource() {
    local name="$1"
    local host="$2"
    local protocol="$3"
    local port="$4"
    local auth_type="$5"
    local username_ref="$6"
    local password_ref="$7"
    local community_ref="$8"
    local snmp_version="$9"
    local snmp_sec_level="${10}"
    local snmp_auth_proto="${11}"
    local snmp_auth_pass_ref="${12}"
    local snmp_priv_proto="${13}"
    local snmp_priv_pass_ref="${14}"
    local endpoint="${15}"
    local token_ref="${16}"
    local api_key_header="${17}"
    local api_key_ref="${18}"
    local http_method="${19}"
    local verify_tls="${20}"

    local result
    local valid
    local reason
    local displayed_protocol

    protocol="$(lower "$protocol")"
    auth_type="$(lower "$auth_type")"

    if [[ -n "$FILTER_RESOURCE" && "$name" != "$FILTER_RESOURCE" ]]; then
        ((SKIPPED_COUNT++))
        return
    fi

    if [[ -n "$FILTER_PROTOCOL" ]]; then
        case "$FILTER_PROTOCOL" in
            snmp)
                [[ "$protocol" == "snmp" ]] || {
                    ((SKIPPED_COUNT++))
                    return
                }
                ;;
            api)
                [[ "$protocol" == "http" || "$protocol" == "https" || "$protocol" == "api" ]] || {
                    ((SKIPPED_COUNT++))
                    return
                }
                ;;
        esac
    fi

    if [[ -z "$name" || -z "$host" || -z "$protocol" || -z "$port" ]]; then
        print_result \
            "${name:-UNKNOWN}" "${host:-UNKNOWN}" "${protocol:-UNKNOWN}" \
            "${port:-?}" 0 "Invalid resource configuration"
        return
    fi

    case "$protocol" in
        snmp)
            displayed_protocol="SNMP${snmp_version}"
            result="$(test_snmp \
                "$host" "$port" "$snmp_version" "$community_ref" \
                "$username_ref" "$snmp_sec_level" "$snmp_auth_proto" \
                "$snmp_auth_pass_ref" "$snmp_priv_proto" "$snmp_priv_pass_ref")"
            ;;
        http|https)
            displayed_protocol="${protocol^^}"
            result="$(test_api \
                "$host" "$protocol" "$port" "$auth_type" "$username_ref" \
                "$password_ref" "$endpoint" "$token_ref" "$api_key_header" \
                "$api_key_ref" "$http_method" "$verify_tls")"
            ;;
        api)
            displayed_protocol="HTTPS"
            result="$(test_api \
                "$host" "https" "$port" "$auth_type" "$username_ref" \
                "$password_ref" "$endpoint" "$token_ref" "$api_key_header" \
                "$api_key_ref" "$http_method" "$verify_tls")"
            ;;
        *)
            print_result "$name" "$host" "$protocol" "$port" 0 "Unsupported protocol"
            return
            ;;
    esac

    valid="${result%%|*}"
    reason="${result#*|}"

    print_result "$name" "$host" "$displayed_protocol" "$port" "$valid" "$reason"
}

###############################################################################
# Lecture du CSV
###############################################################################

process_csv() {
    [[ -f "$CONFIG_FILE" ]] || die "Fichier de configuration introuvable : $CONFIG_FILE"

    local line_number=0
    local found_resource=0

    while IFS=',' read -r \
        name host protocol port auth_type username_ref password_ref community_ref \
        snmp_version snmp_sec_level snmp_auth_proto snmp_auth_pass_ref \
        snmp_priv_proto snmp_priv_pass_ref endpoint token_ref api_key_header \
        api_key_ref http_method verify_tls
    do
        ((line_number++))
        verify_tls="$(trim_cr "${verify_tls:-}")"

        [[ -n "${name//[[:space:]]/}" ]] || continue
        [[ "$name" == \#* ]] && continue

        if (( line_number == 1 )) && [[ "$(lower "$name")" == "name" ]]; then
            continue
        fi

        found_resource=1

        process_resource \
            "$name" "$host" "$protocol" "$port" "$auth_type" \
            "$username_ref" "$password_ref" "$community_ref" "$snmp_version" \
            "$snmp_sec_level" "$snmp_auth_proto" "$snmp_auth_pass_ref" \
            "$snmp_priv_proto" "$snmp_priv_pass_ref" "$endpoint" "$token_ref" \
            "$api_key_header" "$api_key_ref" "$http_method" "$verify_tls"
    done < "$CONFIG_FILE"

    (( found_resource )) || die "Aucune ressource dans $CONFIG_FILE"
}

###############################################################################
# Résumé
###############################################################################

print_summary() {
    printf '\n%s---%s\n\n' "$BOLD" "$RESET"
    printf '%sRésumé des tests%s\n\n' "$BOLD" "$RESET"

    printf 'Ressources testées     : %d\n' "$TESTED_COUNT"
    printf 'Ressources valides     : %b%d%b\n' "$GREEN" "$VALID_COUNT" "$RESET"
    printf 'Ressources non valides : %b%d%b\n' "$RED" "$INVALID_COUNT" "$RESET"

    if (( VERBOSE && SKIPPED_COUNT > 0 )); then
        printf 'Ressources ignorées    : %d\n' "$SKIPPED_COUNT"
    fi
}

###############################################################################
# Main
###############################################################################

main() {
    parse_args "$@"

    check_dependencies || exit 2
    load_secrets
    create_runtime_dir

    printf '%sVérification des credentials de supervision%s\n' "$BOLD" "$RESET"
    printf 'Configuration : %s\n\n' "$CONFIG_FILE"

    print_header
    process_csv
    print_summary

    if (( TESTED_COUNT == 0 )); then
        printf '\n%sAucune ressource ne correspond aux filtres.%s\n' "$YELLOW" "$RESET"
        exit 2
    fi

    (( INVALID_COUNT > 0 )) && exit 1
    exit 0
}

main "$@"
