#!/usr/bin/env bash
# check_credentials.sh - SNMP / HTTP(S) / Veeam credential checks
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/resources.csv}"
SECRETS_FILE="${SECRETS_FILE:-$SCRIPT_DIR/secrets.env}"
GLOBAL_TIMEOUT="${GLOBAL_TIMEOUT:-10}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-5}"
CURL_MAX_TIME="${CURL_MAX_TIME:-10}"
SNMP_TIMEOUT="${SNMP_TIMEOUT:-2}"
SNMP_RETRIES="${SNMP_RETRIES:-0}"
SNMP_TEST_OID="${SNMP_TEST_OID:-1.3.6.1.2.1.1.5}"
VEEAM_API_VERSION_DEFAULT="${VEEAM_API_VERSION_DEFAULT:-1.3-rev1}"
FILTER_RESOURCE=""; FILTER_PROTOCOL=""; VERBOSE=0
VALID_COUNT=0; INVALID_COUNT=0; TESTED_COUNT=0; SKIPPED_COUNT=0

if [[ -t 1 && "${NO_COLOR:-0}" != 1 ]]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; RESET=""; fi

RUNTIME_DIR=""
cleanup(){ [[ -n "$RUNTIME_DIR" && -d "$RUNTIME_DIR" ]] && rm -rf -- "$RUNTIME_DIR"; }
trap cleanup EXIT HUP INT TERM
log_verbose(){ (( VERBOSE )) && printf '%s[DEBUG]%s %s\n' "$BLUE" "$RESET" "$*" >&2 || true; }
die(){ printf '%sERREUR:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 2; }
lower(){ printf '%s' "${1,,}"; }
trim_cr(){ printf '%s' "${1%$'\r'}"; }

usage(){ cat <<'USAGE'
Usage: ./check_credentials.sh [--resource NOM] [--protocol snmp|api] [--verbose]
       [--config resources.csv] [--secrets secrets.env]

Veeam :
  auth_type=veeam     VBR REST API OAuth2
  auth_type=veeam_em  Enterprise Manager : Basic Auth + POST /api/session
USAGE
}

get_secret(){ local r="${1:-}"; [[ "$r" =~ ^[A-Za-z_][A-Za-z0-9_]*$ && -v "$r" ]] || return 1; printf '%s' "${!r}"; }
require_secret(){ local r="$1" d="$2" v; v="$(get_secret "$r")" || { printf 'Secret absent : %s (%s)' "$d" "$r"; return 1; }; [[ -n "$v" ]] || { printf 'Secret vide : %s (%s)' "$d" "$r"; return 1; }; printf '%s' "$v"; }
curl_escape(){ local v="$1"; [[ "$v" != *$'\n'* && "$v" != *$'\r'* ]] || return 1; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; printf '%s' "$v"; }

check_permissions(){ local m g o; [[ -f "$SECRETS_FILE" ]] || die "Fichier de secrets introuvable : $SECRETS_FILE"; m="$(stat -c '%a' "$SECRETS_FILE")" || die "Permissions illisibles"; g="${m: -2:1}"; o="${m: -1}"; ((10#$g==0 && 10#$o==0)) || die "Permissions non sûres ($m). Utiliser chmod 600 '$SECRETS_FILE'"; }
check_dependencies(){ local miss=() c; for c in curl snmpwalk timeout stat mktemp sed; do command -v "$c" >/dev/null 2>&1 || miss+=("$c"); done; ((${#miss[@]}==0)) || { printf 'Dépendances manquantes : %s\n' "${miss[*]}" >&2; return 1; }; }
init(){ check_dependencies || exit 2; check_permissions; source "$SECRETS_FILE"; umask 077; RUNTIME_DIR="$(mktemp -d "${TMPDIR:-/tmp}/check_credentials.XXXXXX")" || die "mktemp impossible"; chmod 700 "$RUNTIME_DIR"; }

print_header(){ printf '%-28s | %-30s | %-10s | %-6s | %s\n' RESSOURCE IP/FQDN PROTOCOLE PORT RÉSULTAT; printf '%-28s-+-%-30s-+-%-10s-+-%-6s-+-%s\n' ---------------------------- ------------------------------ ---------- ------ ------------------------------------------; }
print_result(){ local n="$1" h="$2" p="$3" po="$4" ok="$5" why="$6" s; if [[ "$ok" == 1 ]]; then s="${GREEN}VALIDE${RESET}"; ((VALID_COUNT++)); else s="${RED}NON VALIDE${RESET}"; ((INVALID_COUNT++)); fi; [[ -n "$why" ]] && s+=" - $why"; ((TESTED_COUNT++)); printf '%-28.28s | %-30.30s | %-10.10s | %-6.6s | %b\n' "$n" "$h" "$p" "$po" "$s"; }

classify_curl(){ case "$1" in 5) echo 'Proxy resolution failure';; 6) echo 'DNS resolution failure';; 7) echo 'Port closed / connection refused';; 28|124) echo Timeout;; 35) echo 'TLS handshake failure';; 52) echo 'Empty response';; 56) echo 'Network receive failure';; 60) echo 'TLS certificate validation failure';; *) echo "Network/curl error (rc=$1)";; esac; }
classify_snmp(){ local t="${1,,}" rc="$2"; if ((rc==124)); then echo Timeout; elif [[ "$t" == *"authentication failure"* || "$t" == *"wrong digest"* || "$t" == *"unknown user"* ]]; then echo 'SNMP authentication failure'; elif [[ "$t" == *"decryption"* ]]; then echo 'SNMP privacy/decryption failure'; elif [[ "$t" == *"timeout"* || "$t" == *"no response"* ]]; then echo 'Timeout / No SNMP response'; elif [[ "$t" == *"no route to host"* || "$t" == *"network is unreachable"* ]]; then echo 'Host unreachable'; elif [[ "$t" == *"unknown host"* || "$t" == *"name or service not known"* ]]; then echo 'DNS resolution failure'; elif [[ "$t" == *"authorization"* || "$t" == *"no access"* ]]; then echo 'SNMP authorization denied'; else echo "SNMP request failed (rc=$rc)"; fi; }

snmp_target(){ [[ -z "$2" || "$2" == 161 ]] && printf '%s' "$1" || printf 'udp:%s:%s' "$1" "$2"; }
test_snmp(){
  local host="$1" port="$2" ver="$3" cref="$4" uref="$5" lvl="$6" aproto="$7" aref="$8" pproto="$9" pref="${10}" target out rc community user apass ppass
  target="$(snmp_target "$host" "$port")"
  case "${ver,,}" in
    1|2|2c)
      community="$(require_secret "$cref" 'SNMP community')" || { printf '0|%s' "$community"; return; }
      [[ "$ver" == 2 ]] && ver=2c
      out="$(timeout "$GLOBAL_TIMEOUT" snmpwalk -v "$ver" -c "$community" -t "$SNMP_TIMEOUT" -r "$SNMP_RETRIES" -Oqv "$target" "$SNMP_TEST_OID" 2>&1)"; rc=$?; community="" ;;
    3)
      user="$(require_secret "$uref" 'SNMPv3 username')" || { printf '0|%s' "$user"; return; }
      case "${lvl,,}" in
        noauthnopriv) out="$(timeout "$GLOBAL_TIMEOUT" snmpwalk -v3 -u "$user" -l noAuthNoPriv -t "$SNMP_TIMEOUT" -r "$SNMP_RETRIES" -Oqv "$target" "$SNMP_TEST_OID" 2>&1)"; rc=$? ;;
        authnopriv) apass="$(require_secret "$aref" 'SNMPv3 auth password')" || { printf '0|%s' "$apass"; return; }; out="$(timeout "$GLOBAL_TIMEOUT" snmpwalk -v3 -u "$user" -l authNoPriv -a "$aproto" -A "$apass" -t "$SNMP_TIMEOUT" -r "$SNMP_RETRIES" -Oqv "$target" "$SNMP_TEST_OID" 2>&1)"; rc=$?; apass="" ;;
        authpriv) apass="$(require_secret "$aref" 'SNMPv3 auth password')" || { printf '0|%s' "$apass"; return; }; ppass="$(require_secret "$pref" 'SNMPv3 privacy password')" || { printf '0|%s' "$ppass"; return; }; out="$(timeout "$GLOBAL_TIMEOUT" snmpwalk -v3 -u "$user" -l authPriv -a "$aproto" -A "$apass" -x "$pproto" -X "$ppass" -t "$SNMP_TIMEOUT" -r "$SNMP_RETRIES" -Oqv "$target" "$SNMP_TEST_OID" 2>&1)"; rc=$?; apass=""; ppass="" ;;
        *) printf '0|Unsupported SNMPv3 security level'; return;;
      esac ;;
    *) printf '0|Unsupported SNMP version'; return;;
  esac
  ((rc==0)) && [[ -n "$out" ]] && { printf '1|SNMP response OK'; return; }
  printf '0|%s' "$(classify_snmp "$out" "$rc")"
}

build_url(){ local e="$4"; [[ "$e" =~ ^https?:// ]] && { printf '%s' "$e"; return; }; [[ -n "$e" ]] || e=/; [[ "$e" == /* ]] || e="/$e"; printf '%s://%s:%s%s' "$2" "$1" "$3" "$e"; }

# Generic HTTP(S) check. Secrets are stored in a temporary curl config (0600), never logged.
test_api(){
  local host="$1" scheme="$2" port="$3" auth="$4" uref="$5" pref="$6" endpoint="$7" tref="$8" keyhdr="$9" keyref="${10}" method="${11:-GET}" tls="${12:-true}"
  local u="" p="" tok="" key="" url cfg code rc esc
  case "${auth,,}" in none|"") ;; basic) u="$(require_secret "$uref" 'API username')" || { printf '0|%s' "$u"; return; }; p="$(require_secret "$pref" 'API password')" || { printf '0|%s' "$p"; return; };; bearer) tok="$(require_secret "$tref" 'Bearer token')" || { printf '0|%s' "$tok"; return; };; apikey|api_key) key="$(require_secret "$keyref" 'API key')" || { printf '0|%s' "$key"; return; };; *) printf '0|Unsupported API authentication type'; return;; esac
  url="$(build_url "$host" "$scheme" "$port" "$endpoint")"; cfg="$RUNTIME_DIR/api_${BASHPID}_${RANDOM}.conf"; : >"$cfg"; chmod 600 "$cfg"
  { esc="$(curl_escape "$url")"; printf 'url = "%s"\nrequest = "%s"\nsilent\nshow-error\noutput = "/dev/null"\nwrite-out = "%%{http_code}"\nconnect-timeout = "%s"\nmax-time = "%s"\n' "$esc" "$method" "$CURL_CONNECT_TIMEOUT" "$CURL_MAX_TIME"; [[ "$(lower "$tls")" =~ ^(false|no|0)$ ]] && echo insecure; case "${auth,,}" in basic) esc="$(curl_escape "$u:$p")"; printf 'user = "%s"\nbasic\n' "$esc";; bearer) esc="$(curl_escape "Authorization: Bearer $tok")"; printf 'header = "%s"\n' "$esc";; apikey|api_key) esc="$(curl_escape "$keyhdr: $key")"; printf 'header = "%s"\n' "$esc";; esac; } >>"$cfg"
  u=""; p=""; tok=""; key=""; code="$(timeout "$GLOBAL_TIMEOUT" curl --disable --config "$cfg" 2>/dev/null)"; rc=$?; rm -f "$cfg"
  ((rc==0)) || { printf '0|%s' "$(classify_curl "$rc")"; return; }
  case "$code" in 2??|3??) printf '1|HTTP %s' "$code";; 401) printf '0|HTTP 401 - Authentication failed';; 403) printf '0|HTTP 403 - Forbidden';; 404) printf '0|HTTP 404 - Endpoint not found';; 5??) printf '0|HTTP %s - Server error' "$code";; *) printf '0|HTTP %s' "${code:-000}";; esac
}

# Veeam VBR REST API OAuth2. Kept for environments using /api/oauth2/token.
test_veeam(){
  local host="$1" port="$2" uref="$3" pref="$4" tls="${5:-true}" ver="${6:-$VEEAM_API_VERSION_DEFAULT}" u p uf pf cfg response code body token vcfg vcode rc esc
  u="$(require_secret "$uref" 'Veeam username')" || { printf '0|%s' "$u"; return; }; p="$(require_secret "$pref" 'Veeam password')" || { printf '0|%s' "$p"; return; }
  uf="$RUNTIME_DIR/vu_${RANDOM}"; pf="$RUNTIME_DIR/vp_${RANDOM}"; cfg="$RUNTIME_DIR/va_${RANDOM}.conf"; printf %s "$u" >"$uf"; printf %s "$p" >"$pf"; chmod 600 "$uf" "$pf"; : >"$cfg"; chmod 600 "$cfg"
  { printf 'url = "https://%s:%s/api/oauth2/token"\nrequest = "POST"\nsilent\nshow-error\nconnect-timeout = "%s"\nmax-time = "%s"\nheader = "Content-Type: application/x-www-form-urlencoded"\nheader = "x-api-version: %s"\ndata-urlencode = "grant_type=password"\ndata-urlencode = "username@%s"\ndata-urlencode = "password@%s"\nwrite-out = "\\n%%{http_code}"\n' "$host" "$port" "$CURL_CONNECT_TIMEOUT" "$CURL_MAX_TIME" "$ver" "$uf" "$pf"; [[ "$(lower "$tls")" =~ ^(false|no|0)$ ]] && echo insecure; } >>"$cfg"
  u=""; p=""; response="$(timeout "$GLOBAL_TIMEOUT" curl --disable --config "$cfg" 2>/dev/null)"; rc=$?; rm -f "$cfg" "$uf" "$pf"; ((rc==0)) || { printf '0|%s' "$(classify_curl "$rc")"; return; }
  code="${response##*$'\n'}"; body="${response%$'\n'*}"; [[ "$code" == 200 ]] || { printf '0|Veeam OAuth authentication failed (HTTP %s)' "$code"; return; }; token="$(printf %s "$body" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"; [[ -n "$token" ]] || { printf '0|Veeam access_token missing'; return; }
  vcfg="$RUNTIME_DIR/vv_${RANDOM}.conf"; : >"$vcfg"; chmod 600 "$vcfg"; esc="$(curl_escape "Authorization: Bearer $token")"; { printf 'url = "https://%s:%s/api/v1/serverInfo"\nrequest = "GET"\nsilent\nshow-error\noutput = "/dev/null"\nwrite-out = "%%{http_code}"\nheader = "%s"\nheader = "x-api-version: %s"\n' "$host" "$port" "$esc" "$ver"; [[ "$(lower "$tls")" =~ ^(false|no|0)$ ]] && echo insecure; } >>"$vcfg"; token=""; vcode="$(timeout "$GLOBAL_TIMEOUT" curl --disable --config "$vcfg" 2>/dev/null)"; rc=$?; rm -f "$vcfg"; ((rc==0)) || { printf '0|%s' "$(classify_curl "$rc")"; return; }; [[ "$vcode" == 200 ]] && printf '1|Veeam authentication OK (HTTP 200)' || printf '0|Veeam serverInfo failed (HTTP %s)' "$vcode"
}

# Veeam Enterprise Manager: reproduit exactement la méthode validée
# curl -k -u "user:password" -X POST "https://FQDN/api/session".
# Note: --user place brièvement les credentials dans argv du processus curl.
test_veeam_em(){
  local host="$1" scheme="$2" port="$3" uref="$4" pref="$5" endpoint="${6:-/api/session}" tls="${7:-true}"
  local u p url code rc

  u="$(require_secret "$uref" 'Veeam Enterprise Manager username')" || { printf '0|%s' "$u"; return; }
  p="$(require_secret "$pref" 'Veeam Enterprise Manager password')" || { printf '0|%s' "$p"; return; }
  [[ -n "$endpoint" ]] || endpoint=/api/session
  url="$(build_url "$host" "$scheme" "$port" "$endpoint")"

  log_verbose "Veeam EM host=$host port=$port endpoint=$endpoint auth=basic"

  if [[ "$(lower "$tls")" =~ ^(false|no|0)$ ]]; then
    code="$(timeout "$GLOBAL_TIMEOUT" curl --disable --silent --show-error --insecure --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" --output /dev/null --write-out '%{http_code}' --user "$u:$p" --request POST "$url" 2>/dev/null)"
    rc=$?
  else
    code="$(timeout "$GLOBAL_TIMEOUT" curl --disable --silent --show-error --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" --output /dev/null --write-out '%{http_code}' --user "$u:$p" --request POST "$url" 2>/dev/null)"
    rc=$?
  fi

  u=""; p=""
  ((rc==0)) || { printf '0|%s' "$(classify_curl "$rc")"; return; }
  case "$code" in
    2??) printf '1|Veeam Enterprise Manager authentication OK (HTTP %s)' "$code" ;;
    401) printf '0|Veeam Enterprise Manager authentication failed (HTTP 401)' ;;
    403) printf '0|Veeam Enterprise Manager authentication forbidden (HTTP 403)' ;;
    404) printf '0|Veeam Enterprise Manager session endpoint not found (HTTP 404)' ;;
    405) printf '0|Veeam Enterprise Manager POST not allowed (HTTP 405)' ;;
    5??) printf '0|Veeam Enterprise Manager server error (HTTP %s)' "$code" ;;
    *) printf '0|Veeam Enterprise Manager session failed (HTTP %s)' "${code:-000}" ;;
  esac
}

parse_args(){ while (($#)); do case "$1" in --resource) FILTER_RESOURCE="$2"; shift 2;; --protocol) FILTER_PROTOCOL="$(lower "$2")"; [[ "$FILTER_PROTOCOL" =~ ^(snmp|api)$ ]] || die '--protocol doit être snmp ou api'; shift 2;; --verbose) VERBOSE=1; shift;; --config) CONFIG_FILE="$2"; shift 2;; --secrets) SECRETS_FILE="$2"; shift 2;; -h|--help) usage; exit 0;; *) die "Option inconnue : $1";; esac; done; }

process_resource(){
  local name="$1" host="$2" proto="$3" port="$4" auth="$5" uref="$6" pref="$7" cref="$8" ver="$9" lvl="${10}" aproto="${11}" aref="${12}" pproto="${13}" privref="${14}" endpoint="${15}" tref="${16}" keyhdr="${17}" keyref="${18}" method="${19}" tls="${20}" apiver="${21:-}" result display scheme ok why
  proto="$(lower "$proto")"; auth="$(lower "$auth")"; [[ -n "$FILTER_RESOURCE" && "$name" != "$FILTER_RESOURCE" ]] && { ((SKIPPED_COUNT++)); return; }; [[ "$FILTER_PROTOCOL" == snmp && "$proto" != snmp ]] && { ((SKIPPED_COUNT++)); return; }; [[ "$FILTER_PROTOCOL" == api && ! "$proto" =~ ^(http|https|api)$ ]] && { ((SKIPPED_COUNT++)); return; }
  case "$proto" in snmp) display="SNMP$ver"; result="$(test_snmp "$host" "$port" "$ver" "$cref" "$uref" "$lvl" "$aproto" "$aref" "$pproto" "$privref")";; http|https|api) scheme="$proto"; [[ "$scheme" == api ]] && scheme=https; case "$auth" in veeam) display=VEEAM; result="$(test_veeam "$host" "$port" "$uref" "$pref" "$tls" "$apiver")";; veeam_em) display=VEEAM-EM; result="$(test_veeam_em "$host" "$scheme" "$port" "$uref" "$pref" "$endpoint" "$tls")";; *) display="${scheme^^}"; result="$(test_api "$host" "$scheme" "$port" "$auth" "$uref" "$pref" "$endpoint" "$tref" "$keyhdr" "$keyref" "$method" "$tls")";; esac;; *) print_result "$name" "$host" "$proto" "$port" 0 'Unsupported protocol'; return;; esac
  ok="${result%%|*}"; why="${result#*|}"; print_result "$name" "$host" "$display" "$port" "$ok" "$why"
}

process_csv(){
  [[ -f "$CONFIG_FILE" ]] || die "Fichier de configuration introuvable : $CONFIG_FILE"; local line=0 found=0
  while IFS=',' read -r name host proto port auth uref pref cref ver lvl aproto aref pproto privref endpoint tref keyhdr keyref method tls apiver; do ((line++)); tls="$(trim_cr "${tls:-}")"; apiver="$(trim_cr "${apiver:-}")"; [[ -z "${name//[[:space:]]/}" || "$name" == \#* ]] && continue; ((line==1)) && [[ "$(lower "$name")" == name ]] && continue; found=1; process_resource "$name" "$host" "$proto" "$port" "$auth" "$uref" "$pref" "$cref" "$ver" "$lvl" "$aproto" "$aref" "$pproto" "$privref" "$endpoint" "$tref" "$keyhdr" "$keyref" "$method" "$tls" "$apiver"; done <"$CONFIG_FILE"
  ((found)) || die "Aucune ressource dans $CONFIG_FILE"
}

main(){ parse_args "$@"; init; printf '%sVérification des credentials de supervision%s\nConfiguration : %s\n\n' "$BOLD" "$RESET" "$CONFIG_FILE"; print_header; process_csv; printf '\n%sRésumé :%s %b%d valide(s)%b / %b%d non valide(s)%b\n' "$BOLD" "$RESET" "$GREEN" "$VALID_COUNT" "$RESET" "$RED" "$INVALID_COUNT" "$RESET"; ((TESTED_COUNT)) || exit 2; ((INVALID_COUNT)) && exit 1; exit 0; }
main "$@"
