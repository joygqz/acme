#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly DEFAULT_KEY_TYPE="ec-256"
readonly DEFAULT_CA_SERVER="letsencrypt"
readonly DEFAULT_DNS_PROVIDER="dns_cf"
readonly DEFAULT_ACME_HOME="/root/.acme.sh"
readonly ACME_HOME="${ACME_HOME:-$DEFAULT_ACME_HOME}"
readonly ACME_INSTALL_URL="https://get.acme.sh"
readonly DNS_API_DOC_URL="https://go-acme.github.io/lego/dns/"
readonly REPO_URL="https://github.com/joygqz/acme"
readonly SCRIPT_RAW_URL="https://raw.githubusercontent.com/joygqz/acme/main/acmec.sh"
readonly SCRIPT_VERSION="v1.0.0"
readonly DEFAULT_CACHE_HOME="/root/.acmec.sh"
readonly CACHE_HOME="${ACME_CACHE_HOME:-$DEFAULT_CACHE_HOME}"
readonly CACHE_PREFS_FILE="$CACHE_HOME/preferences.tsv"
readonly CACHE_LEGACY_SECRETS_FILE="$CACHE_HOME/secrets.tsv"
readonly CACHE_SECRETS_DIR="$CACHE_HOME/secrets.d"
readonly CACHE_SCHEMA_VERSION="2"
readonly LOCK_FILE="/var/lock/acmec.sh.lock"
readonly CURL_RETRY_COUNT="3"
readonly CURL_RETRY_DELAY="1"
readonly SCRIPT_CHECK_CONNECT_TIMEOUT="5"
readonly SCRIPT_CHECK_MAX_TIME="15"
readonly SCRIPT_UPDATE_CONNECT_TIMEOUT="10"
readonly SCRIPT_UPDATE_MAX_TIME="25"
readonly INSTALL_CONNECT_TIMEOUT="10"
readonly DNS_PROVIDER_TABLE_COLUMNS="4"
readonly DNS_PROVIDER_TABLE_CELL_WIDTH="20"
readonly -a MENU_HANDLERS=( "" "list_certs" "create_cert" "update_cert" "delete_cert" "update_script" "uninstall_script" )
readonly -a MENU_LABELS=( "" "证书清单" "签发证书" "更新证书路径" "删除证书" "升级脚本" "卸载工具" )
readonly MENU_UPDATE_SCRIPT_HANDLER="update_script"
readonly MENU_MAX_CHOICE="$(( ${#MENU_HANDLERS[@]} - 1 ))"

readonly ENV_HAS_EMAIL="${EMAIL+1}"
readonly ENV_HAS_ISSUE_KEY_TYPE="${ISSUE_KEY_TYPE+1}"
readonly ENV_HAS_ISSUE_CA_SERVER="${ISSUE_CA_SERVER+1}"
readonly ENV_HAS_ISSUE_INCLUDE_WILDCARD="${ISSUE_INCLUDE_WILDCARD+1}"
readonly ENV_HAS_ISSUE_FORCE_RENEW="${ISSUE_FORCE_RENEW+1}"
readonly ENV_HAS_DNS_PROVIDER="${DNS_PROVIDER+1}"
readonly ENV_HAS_DNS_API_ENV_VARS="${DNS_API_ENV_VARS+1}"
readonly ENV_HAS_DEPLOY_BASE_DIR="${DEPLOY_BASE_DIR+1}"

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
ISSUE_KEY_TYPE="${ISSUE_KEY_TYPE:-$DEFAULT_KEY_TYPE}"
ISSUE_CA_SERVER="${ISSUE_CA_SERVER:-$DEFAULT_CA_SERVER}"
ISSUE_INCLUDE_WILDCARD="${ISSUE_INCLUDE_WILDCARD:-0}"
ISSUE_FORCE_RENEW="${ISSUE_FORCE_RENEW:-0}"
DNS_PROVIDER="${DNS_PROVIDER:-$DEFAULT_DNS_PROVIDER}"
DNS_API_ENV_VARS="${DNS_API_ENV_VARS:-}"
DEPLOY_BASE_DIR="${DEPLOY_BASE_DIR:-/etc/ssl}"
PKG_TYPE=""
CRON_SERVICE=""
ACME_SH="$ACME_HOME/acme.sh"
LOCK_FD=""
UPDATE_AVAILABLE_VERSION=""
DNS_API_ENV_LAST_KEYS=""

curl_https() {
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location "$@"
}

curl_script_raw_retry() {
  curl_https --retry "$CURL_RETRY_COUNT" --retry-delay "$CURL_RETRY_DELAY" "$@" "$SCRIPT_RAW_URL"
}

resolve_script_path() {
  local source_path="${BASH_SOURCE[0]}"
  local source_dir source_name
  if [[ -z "$source_path" ]]; then
    return 1
  fi

  if [[ "$source_path" != /* ]]; then
    source_dir="$(cd "$(dirname "$source_path")" && pwd)" || return 1
    source_name="$(basename "$source_path")"
    source_path="${source_dir}/${source_name}"
  fi

  printf '%s\n' "$source_path"
}

resolve_script_path_or_error() {
  local target_var="$1"
  local error_msg="${2:-解析脚本路径失败}"
  local resolved_path
  if ! resolved_path="$(resolve_script_path)"; then
    err "$error_msg"
    return 1
  fi
  printf -v "$target_var" '%s' "$resolved_path"
}

extract_script_version() {
  local input="${1:--}"
  awk '
    BEGIN {
      found = 0
    }
    {
      if (found) {
        next
      }

      line = $0
      sub(/\r$/, "", line)

      if (line ~ /^[[:space:]]*(readonly[[:space:]]+)?SCRIPT_VERSION[[:space:]]*=/) {
        sub(/^[[:space:]]*(readonly[[:space:]]+)?SCRIPT_VERSION[[:space:]]*=[[:space:]]*/, "", line)
        sub(/[[:space:]]*(#.*)?$/, "", line)

        if (length(line) >= 2) {
          first = substr(line, 1, 1)
          last = substr(line, length(line), 1)
          if (first == last && (first == "\"" || first == "\047")) {
            line = substr(line, 2, length(line) - 2)
          }
        }

        if (line != "") {
          print line
          found = 1
        }
      }
    }
  ' "$input"
}

parse_semver() {
  local version="$1"
  local regex='^v?([0-9]+)\.([0-9]+)\.([0-9]+)([-+].*)?$'

  [[ "$version" =~ $regex ]] || return 1
  printf '%s\t%s\t%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
}

fetch_remote_script_version() {
  local remote_version
  if ! remote_version="$(curl_script_raw_retry --connect-timeout "$SCRIPT_CHECK_CONNECT_TIMEOUT" --max-time "$SCRIPT_CHECK_MAX_TIME" 2>/dev/null | extract_script_version)"; then
    return 1
  fi

  [[ -n "$remote_version" ]] || return 1
  printf '%s\n' "$remote_version"
}

is_version_newer() {
  local candidate="$1"
  local baseline="$2"
  local candidate_major candidate_minor candidate_patch
  local baseline_major baseline_minor baseline_patch
  [[ "$candidate" != "$baseline" ]] || return 1
  IFS=$'\t' read -r candidate_major candidate_minor candidate_patch <<< "$(parse_semver "$candidate")" || return 1
  IFS=$'\t' read -r baseline_major baseline_minor baseline_patch <<< "$(parse_semver "$baseline")" || return 1

  if ((10#$candidate_major != 10#$baseline_major)); then
    ((10#$candidate_major > 10#$baseline_major))
    return
  fi
  if ((10#$candidate_minor != 10#$baseline_minor)); then
    ((10#$candidate_minor > 10#$baseline_minor))
    return
  fi
  if ((10#$candidate_patch != 10#$baseline_patch)); then
    ((10#$candidate_patch > 10#$baseline_patch))
    return
  fi
  return 1
}

check_script_update() {
  local remote_version
  UPDATE_AVAILABLE_VERSION=""

  if ! remote_version="$(fetch_remote_script_version)"; then
    return
  fi

  if is_version_newer "$remote_version" "$SCRIPT_VERSION"; then
    UPDATE_AVAILABLE_VERSION="$remote_version"
  fi
}

remove_file_quietly() {
  local file_path="$1"
  [[ -n "$file_path" ]] || return
  rm -f "$file_path" >/dev/null 2>&1 || true
}

is_unsafe_delete_target() {
  local dir_path="$1"
  local resolved_path=""
  case "$dir_path" in
    ""|"/"|"."|".."|"/."|"/.."|*/..|*"/../"*|*/.|*"/./"*)
      return 0
      ;;
  esac

  if command_exists realpath; then
    resolved_path="$(realpath -m -- "$dir_path" 2>/dev/null || true)"
  elif command_exists readlink; then
    resolved_path="$(readlink -f -- "$dir_path" 2>/dev/null || true)"
  fi

  case "$resolved_path" in
    "/"|"/."|"/..")
      return 0
      ;;
  esac
  return 1
}

remove_dir_recursively_if_exists() {
  local dir_path="$1"
  if is_unsafe_delete_target "$dir_path"; then
    return 1
  fi
  [[ -d "$dir_path" ]] || return 0
  rm -rf -- "$dir_path"
}

remove_file_and_error() {
  local file_path="$1"
  shift
  remove_file_quietly "$file_path"
  err "$*"
}

ensure_cache_home() {
  if [[ ! -d "$CACHE_HOME" ]]; then
    mkdir -p "$CACHE_HOME" || return 1
  fi

  chmod 700 "$CACHE_HOME" >/dev/null 2>&1 || true
}

normalize_cache_value() {
  local value="$1"
  value="${value//$'\t'/ }"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"
  printf '%s' "$value"
}

read_cache_entry() {
  local cache_file="$1"
  local key="$2"

  [[ -f "$cache_file" ]] || return 1
  awk -F'\t' -v key="$key" '
    $1 == key {
      start = length($1) + 2
      if (start > (length($0) + 1)) {
        print ""
      } else {
        print substr($0, start)
      }
      found = 1
      exit
    }
    END {
      if (!found) {
        exit 1
      }
    }
  ' "$cache_file"
}

load_cache_entry_into_var() {
  local cache_file="$1"
  local key="$2"
  local target_var="$3"
  local skip_if_env="${4:-}"
  local value

  if [[ -n "$skip_if_env" ]]; then
    return
  fi

  if value="$(read_cache_entry "$cache_file" "$key")"; then
    printf -v "$target_var" '%s' "$value"
  fi
}

write_cache_entries() {
  local cache_file="$1"
  shift

  local cache_dir cache_base tmp_file key value
  cache_dir="$(dirname "$cache_file")"
  cache_base="$(basename "$cache_file")"

  ensure_cache_home || return 1
  if [[ "$cache_dir" != "$CACHE_HOME" ]]; then
    mkdir -p "$cache_dir" || return 1
    chmod 700 "$cache_dir" >/dev/null 2>&1 || true
  fi

  tmp_file="$(mktemp "${cache_dir}/.${cache_base}.XXXXXX")" || return 1
  chmod 600 "$tmp_file" >/dev/null 2>&1 || true

  while [[ "$#" -ge 2 ]]; do
    key="$1"
    value="$(normalize_cache_value "$2")"
    shift 2
    printf '%s\t%s\n' "$key" "$value" >> "$tmp_file"
  done

  if [[ "$#" -ne 0 ]]; then
    remove_file_quietly "$tmp_file"
    return 1
  fi

  if ! mv "$tmp_file" "$cache_file"; then
    remove_file_quietly "$tmp_file"
    return 1
  fi

  chmod 600 "$cache_file" >/dev/null 2>&1 || true
}

load_cached_preferences() {
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "EMAIL" "EMAIL" "$ENV_HAS_EMAIL"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "ISSUE_KEY_TYPE" "ISSUE_KEY_TYPE" "$ENV_HAS_ISSUE_KEY_TYPE"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "ISSUE_CA_SERVER" "ISSUE_CA_SERVER" "$ENV_HAS_ISSUE_CA_SERVER"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "ISSUE_INCLUDE_WILDCARD" "ISSUE_INCLUDE_WILDCARD" "$ENV_HAS_ISSUE_INCLUDE_WILDCARD"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "ISSUE_FORCE_RENEW" "ISSUE_FORCE_RENEW" "$ENV_HAS_ISSUE_FORCE_RENEW"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "DNS_PROVIDER" "DNS_PROVIDER" "$ENV_HAS_DNS_PROVIDER"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "DEPLOY_BASE_DIR" "DEPLOY_BASE_DIR" "$ENV_HAS_DEPLOY_BASE_DIR"
}

load_cached_secrets() {
  local provider_slug secrets_file cached_value=""
  [[ -n "$ENV_HAS_DNS_API_ENV_VARS" ]] && return 0

  provider_slug="$(sanitize_provider_cache_key "$DNS_PROVIDER")"
  secrets_file="$CACHE_SECRETS_DIR/${provider_slug}.tsv"
  if cached_value="$(read_cache_entry "$secrets_file" "DNS_API_ENV_VARS" 2>/dev/null)"; then
    DNS_API_ENV_VARS="$cached_value"
    return 0
  fi

  # Fallback for older single-file cache.
  if cached_value="$(read_cache_entry "$CACHE_LEGACY_SECRETS_FILE" "DNS_API_ENV_VARS" 2>/dev/null)"; then
    DNS_API_ENV_VARS="$cached_value"
  fi
}

reset_persistent_cache_files() {
  remove_file_quietly "$CACHE_PREFS_FILE"
  remove_file_quietly "$CACHE_LEGACY_SECRETS_FILE"
  remove_dir_recursively_if_exists "$CACHE_SECRETS_DIR" || true
}

ensure_cache_schema_compatible() {
  local cached_schema=""

  [[ -f "$CACHE_PREFS_FILE" ]] || return 0
  cached_schema="$(read_cache_entry "$CACHE_PREFS_FILE" "CACHE_SCHEMA_VERSION" 2>/dev/null || true)"

  if [[ "$cached_schema" != "$CACHE_SCHEMA_VERSION" ]]; then
    reset_persistent_cache_files
    warn "缓存结构变更, 已重置缓存"
    return
  fi
}

normalize_cached_settings() {
  normalize_issue_options

  case "$DNS_PROVIDER" in
    dns_[A-Za-z0-9_]*)
      ;;
    *)
      DNS_PROVIDER="$DEFAULT_DNS_PROVIDER"
      ;;
  esac

  if [[ -n "$DNS_API_ENV_VARS" ]] && ! validate_dns_api_env_vars "$DNS_API_ENV_VARS"; then
    DNS_API_ENV_VARS=""
  fi

  [[ -n "$DEPLOY_BASE_DIR" ]] || DEPLOY_BASE_DIR="/etc/ssl"
}

load_persistent_cache() {
  ensure_cache_home || return 1
  ensure_cache_schema_compatible
  load_cached_preferences
  load_cached_secrets
  normalize_cached_settings
}

save_cached_preferences() {
  write_cache_entries "$CACHE_PREFS_FILE" \
    "CACHE_SCHEMA_VERSION" "$CACHE_SCHEMA_VERSION" \
    "EMAIL" "$EMAIL" \
    "ISSUE_KEY_TYPE" "$ISSUE_KEY_TYPE" \
    "ISSUE_CA_SERVER" "$ISSUE_CA_SERVER" \
    "ISSUE_INCLUDE_WILDCARD" "$ISSUE_INCLUDE_WILDCARD" \
    "ISSUE_FORCE_RENEW" "$ISSUE_FORCE_RENEW" \
    "DNS_PROVIDER" "$DNS_PROVIDER" \
    "DEPLOY_BASE_DIR" "$DEPLOY_BASE_DIR"
}

save_cached_secrets() {
  local provider_slug secrets_file
  provider_slug="$(sanitize_provider_cache_key "$DNS_PROVIDER")"
  secrets_file="$CACHE_SECRETS_DIR/${provider_slug}.tsv"
  write_cache_entries "$secrets_file" \
    "DNS_API_ENV_VARS" "${DNS_API_ENV_VARS:-}"

  # Drop old single-file cache after migration.
  remove_file_quietly "$CACHE_LEGACY_SECRETS_FILE"
}

save_persistent_cache() {
  normalize_cached_settings
  save_cached_preferences || return 1
  save_cached_secrets
}

save_cache_or_warn() {
  if ! save_persistent_cache; then
    warn "缓存写入失败: $CACHE_HOME"
  fi
}

load_cache_or_warn() {
  if ! load_persistent_cache; then
    warn "缓存加载失败: $CACHE_HOME"
  fi
}

default_output_dir_for_domain() {
  local domain="$1"
  local base_dir="${DEPLOY_BASE_DIR%/}"

  [[ -n "$base_dir" ]] || base_dir="/"
  if [[ "$base_dir" == "/" ]]; then
    printf '/%s\n' "$domain"
    return
  fi
  printf '%s/%s\n' "$base_dir" "$domain"
}

sanitize_provider_cache_key() {
  local provider="$1"
  provider="${provider//[^A-Za-z0-9_]/_}"
  [[ -n "$provider" ]] || provider="$DEFAULT_DNS_PROVIDER"
  printf '%s\n' "$provider"
}

remember_deploy_base_dir() {
  local domain="$1"
  local output_dir="$2"
  local base_dir

  [[ -n "$domain" && -n "$output_dir" ]] || return
  if [[ "$output_dir" != */"$domain" ]]; then
    return
  fi

  base_dir="${output_dir%/"$domain"}"
  [[ -n "$base_dir" ]] || base_dir="/"
  DEPLOY_BASE_DIR="$base_dir"
}

acquire_lock() {
  mkdir -p "$(dirname "$LOCK_FILE")"

  if ! command_exists flock; then
    warn "未检测到 flock, 跳过并发锁"
    return
  fi

  exec {LOCK_FD}> "$LOCK_FILE"
  if ! flock -n "$LOCK_FD"; then
    die "已有实例运行中"
  fi
}

release_lock() {
  if [[ -n "$LOCK_FD" ]]; then
    flock -u "$LOCK_FD" >/dev/null 2>&1 || true
    exec {LOCK_FD}>&- || true
    LOCK_FD=""
  fi
}

log() {
  printf '%s\n' "$*"
}

err() {
  printf '%s\n' "$*" >&2
}

die() {
  err "$*"
  exit 1
}

warn() {
  err "WARN: $*"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

run_or_error() {
  local error_msg="$1"
  shift

  if ! "$@"; then
    err "$error_msg"
    return 1
  fi
}

get_missing_base_dependencies() {
  local -a missing=()
  local cmd
  for cmd in curl openssl crontab; do
    if ! command_exists "$cmd"; then
      missing+=( "$cmd" )
    fi
  done

  printf '%s\n' "${missing[*]}"
}

is_valid_domain() {
  local domain_name="$1"
  [[ "$domain_name" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

is_valid_email() {
  local email_address="$1"
  [[ "$email_address" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

read_prompt_value() {
  local target_var="$1"
  local prompt="$2"
  local input_value=""
  if ! IFS= read -r -p "$prompt" input_value; then
    die "输入中断"
  fi

  printf -v "$target_var" '%s' "$input_value"
}

ensure_valid_email_input() {
  local target_var="$1"
  local prompt="$2"
  local invalid_msg="$3"
  local value="${!target_var:-}"

  while true; do
    if [[ -z "$value" ]]; then
      read_prompt_value value "$prompt"
    fi

    if is_valid_email "$value"; then
      printf -v "$target_var" '%s' "$value"
      return
    fi

    err "${invalid_msg}: $value"
    value=""
  done
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "需使用 root 运行"
}

detect_os() {
  local os_id os_like
  if [[ ! -f /etc/os-release ]]; then
    die "系统识别失败: 缺少 /etc/os-release"
  fi

  # shellcheck disable=SC1091
  source /etc/os-release

  os_id="${ID:-}"
  os_like="${ID_LIKE:-}"

  if [[ "$os_id" =~ (ubuntu|debian) ]] || [[ "$os_like" =~ (debian) ]]; then
    PKG_TYPE="apt"
    CRON_SERVICE="cron"
  elif [[ "$os_id" =~ (centos|rhel|rocky|almalinux|fedora) ]] || [[ "$os_like" =~ (rhel|fedora|centos) ]]; then
    if command_exists dnf; then
      PKG_TYPE="dnf"
    else
      PKG_TYPE="yum"
    fi
    CRON_SERVICE="crond"
  else
    die "不支持当前系统: ID=${os_id}, ID_LIKE=${os_like}"
  fi
}

has_ca_bundle() {
  [[ -r /etc/ssl/certs/ca-certificates.crt || -r /etc/pki/tls/certs/ca-bundle.crt ]]
}

warn_service_action_failed() {
  local action="$1"
  warn "${CRON_SERVICE} ${action}失败, 需手动处理"
}

enable_non_systemd_service_autostart() {
  if command_exists chkconfig; then
    if ! chkconfig "$CRON_SERVICE" on >/dev/null 2>&1; then
      warn_service_action_failed "设置开机自启"
    fi
    return
  fi

  if command_exists update-rc.d; then
    if ! update-rc.d "$CRON_SERVICE" defaults >/dev/null 2>&1; then
      warn_service_action_failed "设置开机自启"
    fi
  fi
}

ensure_cron_service_running() {
  if command_exists systemctl && [[ -d /run/systemd/system ]]; then
    if ! systemctl is-enabled "$CRON_SERVICE" >/dev/null 2>&1; then
      if ! systemctl enable "$CRON_SERVICE" >/dev/null 2>&1; then
        warn_service_action_failed "启用"
      fi
    fi

    if ! systemctl is-active "$CRON_SERVICE" >/dev/null 2>&1; then
      if ! systemctl start "$CRON_SERVICE" >/dev/null 2>&1; then
        warn_service_action_failed "启动"
      fi
    fi
    return
  fi

  if ! command_exists service; then
    warn "未检测到 systemctl/service, 跳过 ${CRON_SERVICE} 自动管理"
    return
  fi

  enable_non_systemd_service_autostart
  if ! service "$CRON_SERVICE" start >/dev/null 2>&1; then
    warn_service_action_failed "启动"
  fi
}

install_deps() {
  local missing_deps
  missing_deps="$(get_missing_base_dependencies)"
  if [[ -z "$missing_deps" ]] && has_ca_bundle; then
    ensure_cron_service_running
    return
  fi

  case "$PKG_TYPE" in
    apt)
      command_exists apt-get || die "缺少命令: apt-get"
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y --no-install-recommends curl cron openssl ca-certificates
      ;;
    yum|dnf)
      command_exists "$PKG_TYPE" || die "缺少命令: ${PKG_TYPE}"
      "$PKG_TYPE" install -y curl cronie openssl ca-certificates
      ;;
    *)
      die "不支持的包管理器: $PKG_TYPE"
      ;;
  esac

  missing_deps="$(get_missing_base_dependencies)"
  if [[ -n "$missing_deps" ]]; then
    die "依赖安装后缺少命令: $missing_deps"
  fi
  if ! has_ca_bundle; then
    die "依赖安装后缺少 CA 证书"
  fi

  ensure_cron_service_running
}

install_acme_sh() {
  if [[ ! -x "$ACME_SH" ]]; then
    curl_https --retry "$CURL_RETRY_COUNT" --retry-delay "$CURL_RETRY_DELAY" --connect-timeout "$INSTALL_CONNECT_TIMEOUT" "$ACME_INSTALL_URL" \
      | sh -s "email=$EMAIL" --home "$ACME_HOME" --no-profile
  fi

  if [[ ! -x "$ACME_SH" ]]; then
    die "ACME 客户端安装失败: 未找到 $ACME_SH"
  fi

  if [[ "${ACME_AUTO_UPGRADE:-0}" == "1" ]]; then
    "$ACME_SH" --upgrade --auto-upgrade
  fi
  ensure_default_ca
}

ensure_default_ca() {
  local account_conf="$ACME_HOME/account.conf"
  local current_ca expected_ca
  if [[ -f "$account_conf" ]]; then
    current_ca="$(read_conf_value "$account_conf" "DEFAULT_ACME_SERVER")"
    current_ca="$(trim_outer_quotes "$current_ca")"
  fi

  case "$DEFAULT_CA_SERVER" in
    letsencrypt)
      expected_ca="https://acme-v02.api.letsencrypt.org/directory"
      ;;
    zerossl)
      expected_ca="https://acme.zerossl.com/v2/DV90"
      ;;
    buypass)
      expected_ca="https://api.buypass.com/acme/directory"
      ;;
    *)
      expected_ca="$DEFAULT_CA_SERVER"
      ;;
  esac

  if [[ "$current_ca" == "$DEFAULT_CA_SERVER" || "$current_ca" == "$expected_ca" ]]; then
    return
  fi

  "$ACME_SH" --set-default-ca --server "$DEFAULT_CA_SERVER"
}

prompt_install_email_if_needed() {
  if [[ -x "$ACME_SH" ]]; then
    return
  fi

  ensure_valid_email_input EMAIL "首次部署请输入 ACME 邮箱: " "邮箱格式无效"
}

get_cert_conf_file() {
  local domain="$1"
  local preferred_variant="${2:-}"
  local variant
  local -a conf_candidates=( "ecc" "rsa" )
  local conf_file
  if [[ "$preferred_variant" == "rsa" ]]; then
    conf_candidates=( "rsa" "ecc" )
  fi

  for variant in "${conf_candidates[@]}"; do
    conf_file="$(get_cert_conf_path_by_variant "$domain" "$variant")"
    if [[ -f "$conf_file" ]]; then
      printf '%s\n' "$conf_file"
      return 0
    fi
  done

  return 1
}

is_ecc_variant() {
  local variant="$1"
  [[ "$variant" == "ecc" ]]
}

variant_dir_suffix() {
  local variant="$1"
  if is_ecc_variant "$variant"; then
    printf '%s\n' "_ecc"
    return
  fi
  printf '%s\n' ""
}

get_cert_conf_path_by_variant() {
  local domain="$1"
  local variant="$2"
  local suffix
  suffix="$(variant_dir_suffix "$variant")"
  printf '%s\n' "$ACME_HOME/${domain}${suffix}/${domain}.conf"
}

get_cert_dir_by_variant() {
  local domain="$1"
  local variant="$2"
  local suffix
  suffix="$(variant_dir_suffix "$variant")"
  printf '%s\n' "$ACME_HOME/${domain}${suffix}"
}

cert_variant_exists() {
  local domain="$1"
  local variant="$2"
  local conf_path
  conf_path="$(get_cert_conf_path_by_variant "$domain" "$variant")"
  [[ -f "$conf_path" ]]
}

cert_domain_exists() {
  local domain="$1"
  get_cert_conf_file "$domain" >/dev/null 2>&1
}

cleanup_stale_domain_dirs() {
  local domain="$1"
  local variant variant_dir
  for variant in ecc rsa; do
    variant_dir="$(get_cert_dir_by_variant "$domain" "$variant")"
    if [[ -d "$variant_dir" ]] && ! cert_variant_exists "$domain" "$variant"; then
      remove_dir_recursively_if_exists "$variant_dir"
    fi
  done
}

read_conf_value() {
  local conf_file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$conf_file"
}

select_cert_variant_for_domain() {
  local domain="$1"
  local target_var="$2"
  local has_ecc="0"
  local has_rsa="0"
  local answer
  if cert_variant_exists "$domain" "ecc"; then
    has_ecc="1"
  fi
  if cert_variant_exists "$domain" "rsa"; then
    has_rsa="1"
  fi

  if [[ "$has_ecc" == "1" && "$has_rsa" == "1" ]]; then
    while true; do
      read_prompt_value answer "检测到 ECC/RSA, 请选择 [1] ECC [2] RSA: "
      case "$answer" in
        1)
          printf -v "$target_var" '%s' "ecc"
          return 0
          ;;
        2)
          printf -v "$target_var" '%s' "rsa"
          return 0
          ;;
        *)
          err "选项无效"
          ;;
      esac
    done
  fi

  if [[ "$has_ecc" == "1" ]]; then
    printf -v "$target_var" '%s' "ecc"
    return 0
  fi
  if [[ "$has_rsa" == "1" ]]; then
    printf -v "$target_var" '%s' "rsa"
    return 0
  fi

  return 1
}

key_type_to_variant() {
  local key_type="$1"

  if [[ "$key_type" == ec-* ]]; then
    printf '%s\n' "ecc"
    return
  fi

  printf '%s\n' "rsa"
}

prompt_option_with_default() {
  local target_var="$1"
  local prompt="$2"
  local default_value="$3"
  local invalid_msg="$4"
  shift 4
  local -a option_map=( "$@" )
  local answer
  local option_idx=0

  if (( ${#option_map[@]} == 0 || (${#option_map[@]} % 2) != 0 )); then
    die "选项配置异常: $prompt"
  fi

  while true; do
    read_prompt_value answer "$prompt"
    if [[ -z "$answer" ]]; then
      printf -v "$target_var" '%s' "$default_value"
      return
    fi

    option_idx=0
    while [[ "$option_idx" -lt "${#option_map[@]}" ]]; do
      if [[ "$answer" == "${option_map[$option_idx]}" ]]; then
        printf -v "$target_var" '%s' "${option_map[$((option_idx + 1))]}"
        return
      fi
      option_idx=$((option_idx + 2))
    done

    err "$invalid_msg"
  done
}

prompt_yes_no_with_default() {
  local target_var="$1"
  local prompt="$2"
  local default_value="${3:-0}"
  local answer
  while true; do
    read_prompt_value answer "$prompt"
    case "$answer" in
      "")
        printf -v "$target_var" '%s' "$default_value"
        return
        ;;
      [Nn]|[Nn][Oo])
        printf -v "$target_var" '%s' "0"
        return
        ;;
      [Yy]|[Yy][Ee][Ss])
        printf -v "$target_var" '%s' "1"
        return
        ;;
      *)
        err "请输入 y/n"
        ;;
    esac
  done
}

normalize_issue_options() {
  case "$ISSUE_KEY_TYPE" in
    ec-256|ec-384|2048|4096) ;;
    *) ISSUE_KEY_TYPE="$DEFAULT_KEY_TYPE" ;;
  esac

  case "$ISSUE_CA_SERVER" in
    letsencrypt|zerossl|buypass) ;;
    *) ISSUE_CA_SERVER="$DEFAULT_CA_SERVER" ;;
  esac

  case "$ISSUE_INCLUDE_WILDCARD" in
    0|1) ;;
    *) ISSUE_INCLUDE_WILDCARD="0" ;;
  esac

  case "$ISSUE_FORCE_RENEW" in
    0|1) ;;
    *) ISSUE_FORCE_RENEW="0" ;;
  esac
}

prompt_issue_options() {
  local wildcard_prompt="是否签发泛域名 *.$DOMAIN [y/N]: "
  local force_renew_prompt="是否强制重新签发 [y/N]: "

  normalize_issue_options

  prompt_option_with_default \
    ISSUE_KEY_TYPE \
    "密钥算法 [1] ec-256 [2] ec-384 [3] rsa-2048 [4] rsa-4096 (默认: $ISSUE_KEY_TYPE): " \
    "$ISSUE_KEY_TYPE" \
    "密钥算法选项无效" \
    "1" "ec-256" \
    "2" "ec-384" \
    "3" "2048" \
    "4" "4096"

  prompt_option_with_default \
    ISSUE_CA_SERVER \
    "CA 提供方 [1] letsencrypt [2] zerossl [3] buypass (默认: $ISSUE_CA_SERVER): " \
    "$ISSUE_CA_SERVER" \
    "CA 选项无效" \
    "1" "letsencrypt" \
    "2" "zerossl" \
    "3" "buypass"

  if [[ "$ISSUE_INCLUDE_WILDCARD" == "1" ]]; then
    wildcard_prompt="是否签发泛域名 *.$DOMAIN [Y/n]: "
  fi
  if [[ "$ISSUE_FORCE_RENEW" == "1" ]]; then
    force_renew_prompt="是否强制重新签发 [Y/n]: "
  fi

  prompt_yes_no_with_default ISSUE_INCLUDE_WILDCARD "$wildcard_prompt" "$ISSUE_INCLUDE_WILDCARD"
  prompt_yes_no_with_default ISSUE_FORCE_RENEW "$force_renew_prompt" "$ISSUE_FORCE_RENEW"
}

issue_cert() {
  local -a issue_args=(
    --issue
    --keylength "$ISSUE_KEY_TYPE"
    --server "$ISSUE_CA_SERVER"
    --domain "$DOMAIN"
    --dns "$DNS_PROVIDER"
  )

  if [[ "$ISSUE_INCLUDE_WILDCARD" == "1" ]]; then
    issue_args+=( --domain "*.$DOMAIN" )
  fi

  if [[ "$ISSUE_FORCE_RENEW" == "1" ]]; then
    issue_args+=( --force )
  fi

  "$ACME_SH" "${issue_args[@]}"
}

list_dns_providers() {
  local dnsapi_dir="$ACME_HOME/dnsapi"
  local provider_file providers=""

  [[ -d "$dnsapi_dir" ]] || return 1
  for provider_file in "$dnsapi_dir"/dns_*.sh; do
    [[ -f "$provider_file" ]] || continue
    providers+="${provider_file##*/}"$'\n'
  done
  [[ -n "$providers" ]] || return 1

  printf '%s' "$providers" | sed 's/\.sh$//' | sort -u
}

list_dns_provider_env_keys() {
  local provider="${1:-$DNS_PROVIDER}"
  local provider_file="$ACME_HOME/dnsapi/${provider}.sh"

  [[ -f "$provider_file" ]] || return 1
  grep -Eo '_readaccountconf(_mutable)?[[:space:]]+["'"'"']?[A-Za-z_][A-Za-z0-9_]*["'"'"']?' "$provider_file" \
    | sed -E 's/^_readaccountconf(_mutable)?[[:space:]]+//' \
    | tr -d "\"'" \
    | sort -u
}

print_dns_providers_table() {
  local providers="$1"
  local columns="${2:-$DNS_PROVIDER_TABLE_COLUMNS}"
  local cell_width="${3:-$DNS_PROVIDER_TABLE_CELL_WIDTH}"
  local provider display_provider
  local idx=0

  log "可选 DNS Provider 列表:"
  while IFS= read -r provider; do
    [[ -n "$provider" ]] || continue
    display_provider="$(truncate_text "$provider" "$cell_width")"
    printf '%-*s' "$cell_width" "$display_provider"
    idx=$((idx + 1))
    if ((idx % columns == 0)); then
      printf '\n'
    fi
  done <<< "$providers"

  ((idx > 0)) || return 1
  if ((idx % columns != 0)); then
    printf '\n'
  fi
}

validate_dns_api_env_vars() {
  local env_vars="$1"
  local env_pair env_key env_value
  local -a env_pairs=()

  [[ -n "$env_vars" ]] || return 1
  read -r -a env_pairs <<< "$env_vars"
  ((${#env_pairs[@]} > 0)) || return 1
  for env_pair in "${env_pairs[@]}"; do
    [[ "$env_pair" == *=* ]] || return 1
    env_key="${env_pair%%=*}"
    env_value="${env_pair#*=}"
    [[ -n "$env_key" && -n "$env_value" ]] || return 1
    [[ "$env_key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
  done
}

prompt_dns_provider() {
  local provider_input current_provider providers
  current_provider="$DNS_PROVIDER"

  if providers="$(list_dns_providers)"; then
    print_dns_providers_table "$providers"
  fi

  while true; do
    read_prompt_value provider_input "DNS Provider (默认: $current_provider): "
    provider_input="${provider_input:-$current_provider}"

    if [[ ! "$provider_input" =~ ^dns_[A-Za-z0-9_]+$ ]]; then
      err "DNS Provider 格式无效: $provider_input"
      continue
    fi
    if [[ -d "$ACME_HOME/dnsapi" && ! -f "$ACME_HOME/dnsapi/${provider_input}.sh" ]]; then
      err "未找到 DNS Provider: $provider_input"
      continue
    fi
    DNS_PROVIDER="$provider_input"
    return
  done
}

prompt_dns_api_env_vars() {
  local input_env_vars provider_env_keys="" provider_env_keys_inline="" prompt
  if provider_env_keys="$(list_dns_provider_env_keys "$DNS_PROVIDER")"; then
    provider_env_keys_inline="${provider_env_keys//$'\n'/, }"
    provider_env_keys_inline="${provider_env_keys_inline%, }"
    if [[ -n "$provider_env_keys_inline" ]]; then
      log "当前 DNS 环境变量 Key: $provider_env_keys_inline"
    fi
  fi

  prompt="请输入 DNS 环境变量 (KEY=VALUE, 空格分隔): "
  if [[ -n "$DNS_API_ENV_VARS" ]]; then
    prompt="请输入 DNS 环境变量 (KEY=VALUE, 空格分隔, 留空沿用 $DNS_PROVIDER 缓存): "
  fi

  while true; do
    read_prompt_value input_env_vars "$prompt"
    if [[ -z "$input_env_vars" && -n "$DNS_API_ENV_VARS" ]]; then
      return
    fi
    if validate_dns_api_env_vars "$input_env_vars"; then
      DNS_API_ENV_VARS="$input_env_vars"
      return
    fi
    if [[ -n "$provider_env_keys_inline" ]]; then
      err "环境变量格式无效, 需使用 KEY=VALUE, 可选 Key: $provider_env_keys_inline"
    else
      err "环境变量格式无效, 示例: CF_Token=xxx, 文档: $DNS_API_DOC_URL"
    fi
  done
}

prompt_dns_credentials() {
  local previous_provider="$DNS_PROVIDER"
  prompt_dns_provider
  if [[ "$DNS_PROVIDER" != "$previous_provider" ]]; then
    DNS_API_ENV_VARS=""
    load_cached_secrets
  fi
  prompt_dns_api_env_vars
}

clear_applied_dns_api_env() {
  local env_key
  local -a env_keys=()
  read -r -a env_keys <<< "${DNS_API_ENV_LAST_KEYS:-}"
  ((${#env_keys[@]} > 0)) || {
    DNS_API_ENV_LAST_KEYS=""
    return 0
  }
  for env_key in "${env_keys[@]}"; do
    export "$env_key="
  done
  DNS_API_ENV_LAST_KEYS=""
}

apply_dns_credentials_env() {
  local env_pair env_key env_value
  local -a env_pairs=()

  clear_applied_dns_api_env
  read -r -a env_pairs <<< "${DNS_API_ENV_VARS:-}"
  ((${#env_pairs[@]} > 0)) || return 0
  for env_pair in "${env_pairs[@]}"; do
    env_key="${env_pair%%=*}"
    env_value="${env_pair#*=}"
    export "$env_key=$env_value"
    DNS_API_ENV_LAST_KEYS+="${env_key} "
  done
}

install_cert_to_dir() {
  local cert_domain="$1"
  local cert_dir="$2"
  local cert_variant="$3"
  local -a install_args=(
    --install-cert
    --domain "$cert_domain"
    --key-file "$cert_dir/$cert_domain.key"
    --fullchain-file "$cert_dir/fullchain.cer"
    --cert-file "$cert_dir/cert.cer"
    --ca-file "$cert_dir/ca.cer"
  )

  [[ -n "$cert_variant" ]] || die "证书类型不能为空"

  run_or_error "部署目录创建失败: $cert_dir" mkdir -p "$cert_dir" || return 1
  run_or_error "部署目录权限设置失败: $cert_dir" chmod 755 "$cert_dir" || return 1

  if is_ecc_variant "$cert_variant"; then
    install_args+=( --ecc )
  fi

  run_or_error "证书部署命令执行失败: $cert_domain" "$ACME_SH" "${install_args[@]}" || return 1

  run_or_error "私钥权限设置失败: $cert_dir/$cert_domain.key" chmod 600 "$cert_dir/$cert_domain.key" || return 1
  run_or_error "证书文件权限设置失败: $cert_dir" chmod 644 "$cert_dir/fullchain.cer" "$cert_dir/cert.cer" "$cert_dir/ca.cer" || return 1
}

prompt_existing_cert_domain() {
  local target_var="$1"
  local prompt="$2"
  local raw_list parsed_rows selected_domain
  raw_list="$("$ACME_SH" --list --listraw)" || return 1
  parsed_rows="$(parse_cert_list_rows "$raw_list")"
  if [[ -z "$parsed_rows" ]]; then
    log "未检测到证书记录"
    return 1
  fi

  print_cert_list "$raw_list" "$parsed_rows" || return 1

  while true; do
    selected_domain="$(prompt_domain_value "$prompt")"
    if cert_domain_exists "$selected_domain"; then
      printf -v "$target_var" '%s' "$selected_domain"
      return 0
    fi
    err "未找到证书: $selected_domain"
  done
}

resolve_existing_cert_target() {
  local domain_var="$1"
  local variant_var="$2"
  local prompt="$3"
  local domain variant
  prompt_existing_cert_domain domain "$prompt" || return 1
  select_cert_variant_for_domain "$domain" variant || return 1

  printf -v "$domain_var" '%s' "$domain"
  printf -v "$variant_var" '%s' "$variant"
}

trim_outer_quotes() {
  local value="$1"

  value="${value#\'}"
  value="${value%\'}"
  value="${value#\"}"
  value="${value%\"}"
  printf '%s' "$value"
}

truncate_text() {
  local value="$1"
  local width="$2"

  if [[ "${#value}" -le "$width" ]]; then
    printf '%s' "$value"
    return
  fi

  if [[ "$width" -le 3 ]]; then
    printf '%.*s' "$width" "$value"
    return
  fi

  printf '%.*s...' "$((width - 3))" "$value"
}

get_cert_install_dir() {
  local domain="$1"
  local preferred_variant="${2:-}"
  local conf_file cert_path key_path
  if ! conf_file="$(get_cert_conf_file "$domain" "$preferred_variant")"; then
    printf '%s\n' "-"
    return
  fi

  cert_path="$(read_conf_value "$conf_file" "Le_RealFullChainPath")"
  key_path="$(read_conf_value "$conf_file" "Le_RealKeyPath")"
  cert_path="$(trim_outer_quotes "$cert_path")"
  key_path="$(trim_outer_quotes "$key_path")"

  if [[ -n "$cert_path" ]]; then
    dirname "$cert_path"
    return
  fi
  if [[ -n "$key_path" ]]; then
    dirname "$key_path"
    return
  fi

  printf '%s\n' "-"
}

prompt_output_dir_with_default() {
  local target_var="$1"
  local default_dir="$2"
  local value
  read_prompt_value value "部署目录 (默认: $default_dir): "
  printf -v "$target_var" '%s' "${value:-$default_dir}"
}

prompt_domain_value() {
  local prompt="$1"
  local value
  while true; do
    read_prompt_value value "$prompt"
    if [[ -z "$value" ]]; then
      err "域名不能为空"
      continue
    fi
    if ! is_valid_domain "$value"; then
      err "域名格式无效: $value"
      continue
    fi
    printf '%s\n' "$value"
    return
  done
}

parse_cert_list_rows() {
  local raw_list="$1"
  printf '%s\n' "$raw_list" | awk -F'|' '
    function trim(v) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      return v
    }
    NR == 1 { next }
    NF == 0 { next }
    {
      main_domain = trim($1)
      key_length = trim($2)
      san_domains = trim($3)
      ca = ""
      created = ""
      renew = ""

      # acme.sh 3.1.x: Main_Domain|KeyLength|SAN_Domains|Profile|CA|Created|Renew
      # older acme.sh: Main_Domain|KeyLength|SAN_Domains|CA|Created|Renew
      if (NF >= 7) {
        ca = $5
        created = $6
        renew = $7
      } else if (NF >= 6) {
        ca = $4
        created = $5
        renew = $6
      } else {
        next
      }

      ca = trim(ca)
      created = trim(created)
      renew = trim(renew)

      gsub(/"/, "", key_length)
      if (key_length == "") key_length = "-"
      if (san_domains == "no" || san_domains == "") san_domains = "-"
      if (ca == "") ca = "-"
      if (created == "") created = "-"
      if (renew == "") renew = "-"

      if (main_domain != "") {
        printf "%s\t%s\t%s\t%s\t%s\t%s\n", main_domain, key_length, san_domains, ca, created, renew
      }
    }
  '
}

print_cert_list() {
  local raw_list="$1"
  local parsed_rows="${2:-}"
  local border row_variant
  local main_domain key_length san_domains ca created renew install_dir
  local main_domain_fmt key_length_fmt san_domains_fmt ca_fmt created_fmt renew_fmt install_dir_fmt
  if [[ -z "$parsed_rows" ]]; then
    parsed_rows="$(parse_cert_list_rows "$raw_list")"
  fi
  if [[ -z "$parsed_rows" ]]; then
    log "未检测到证书记录"
    return 0
  fi

  border="+---------------------------+---------+---------------------------+-------------+----------------------+----------------------+----------------------------+"
  printf '\n'
  printf "%s\n" "证书清单"
  printf '\n'
  printf '%s\n' "$border"
  printf "| %-25s | %-7s | %-25s | %-11s | %-20s | %-20s | %-26s |\n" \
    "Domain" "Key" "SAN" "CA" "Created" "Renew" "Install Dir"
  printf '%s\n' "$border"

  while IFS=$'\t' read -r main_domain key_length san_domains ca created renew; do
    row_variant="$(key_type_to_variant "$key_length")"
    install_dir="$(get_cert_install_dir "$main_domain" "$row_variant")"

    main_domain_fmt="$(truncate_text "$main_domain" 25)"
    key_length_fmt="$(truncate_text "$key_length" 7)"
    san_domains_fmt="$(truncate_text "$san_domains" 25)"
    ca_fmt="$(truncate_text "$ca" 11)"
    created_fmt="$(truncate_text "$created" 20)"
    renew_fmt="$(truncate_text "$renew" 20)"
    install_dir_fmt="$(truncate_text "$install_dir" 26)"

    printf "| %-25s | %-7s | %-25s | %-11s | %-20s | %-20s | %-26s |\n" \
      "$main_domain_fmt" \
      "$key_length_fmt" \
      "$san_domains_fmt" \
      "$ca_fmt" \
      "$created_fmt" \
      "$renew_fmt" \
      "$install_dir_fmt"
  done <<< "$parsed_rows"

  printf '%s\n' "$border"
}

list_certs() {
  local raw_list
  raw_list="$("$ACME_SH" --list --listraw)" || return 1
  print_cert_list "$raw_list"
}

create_cert() {
  local cert_variant cert_dir default_output_dir
  DOMAIN="$(prompt_domain_value "请输入域名 (示例: example.com): ")"

  if cert_domain_exists "$DOMAIN"; then
    err "证书已存在: $DOMAIN"
    return 1
  fi

  prompt_dns_credentials
  prompt_issue_options
  cert_variant="$(key_type_to_variant "$ISSUE_KEY_TYPE")"

  cleanup_stale_domain_dirs "$DOMAIN"
  default_output_dir="$(default_output_dir_for_domain "$DOMAIN")"
  prompt_output_dir_with_default OUTPUT_DIR "$default_output_dir"
  apply_dns_credentials_env
  if ! issue_cert; then
    cert_dir="$(get_cert_dir_by_variant "$DOMAIN" "$cert_variant")"
    remove_dir_recursively_if_exists "$cert_dir"
    err "证书签发失败"
    return 1
  fi
  run_or_error "证书部署失败" install_cert_to_dir "$DOMAIN" "$OUTPUT_DIR" "$cert_variant" || return 1
  remember_deploy_base_dir "$DOMAIN" "$OUTPUT_DIR"

  log "证书已签发: $DOMAIN -> $OUTPUT_DIR"
}

update_cert() {
  local target_domain cert_variant cert_dir
  resolve_existing_cert_target target_domain cert_variant "请输入需更新证书路径的域名: " || return 1
  cert_dir="$(get_cert_install_dir "$target_domain" "$cert_variant")"
  if [[ "$cert_dir" == "-" ]]; then
    cert_dir="$(default_output_dir_for_domain "$target_domain")"
  fi
  prompt_output_dir_with_default cert_dir "$cert_dir"

  run_or_error "证书路径更新失败: $target_domain" install_cert_to_dir "$target_domain" "$cert_dir" "$cert_variant" || return 1
  remember_deploy_base_dir "$target_domain" "$cert_dir"
  log "证书路径已更新: $target_domain -> $cert_dir"
}

delete_cert() {
  local target_domain cert_variant acme_dir
  local -a remove_args=()

  resolve_existing_cert_target target_domain cert_variant "请输入待删除证书域名: " || return 1

  remove_args=( --remove --domain "$target_domain" )
  if is_ecc_variant "$cert_variant"; then
    remove_args+=( --ecc )
  fi
  run_or_error "证书删除命令执行失败: $target_domain" "$ACME_SH" "${remove_args[@]}" || return 1

  acme_dir="$(get_cert_dir_by_variant "$target_domain" "$cert_variant")"
  run_or_error "证书目录清理失败: $acme_dir" remove_dir_recursively_if_exists "$acme_dir" || return 1

  log "证书已删除: $target_domain"
}

update_script() {
  local script_path script_dir tmp_file new_version
  resolve_script_path_or_error script_path || return 1

  if [[ ! -f "$script_path" ]]; then
    err "未找到脚本文件: $script_path"
    return 1
  fi

  if [[ ! -w "$script_path" ]]; then
    err "脚本文件不可写: $script_path"
    return 1
  fi

  script_dir="$(dirname "$script_path")"
  if ! tmp_file="$(mktemp "${script_dir}/.acmec.sh.update.XXXXXX")"; then
    err "临时文件创建失败"
    return 1
  fi

  if ! curl_script_raw_retry --connect-timeout "$SCRIPT_UPDATE_CONNECT_TIMEOUT" --max-time "$SCRIPT_UPDATE_MAX_TIME" -o "$tmp_file"; then
    remove_file_and_error "$tmp_file" "升级下载失败"
    return 1
  fi

  if ! bash -n "$tmp_file"; then
    remove_file_and_error "$tmp_file" "升级脚本语法检查失败"
    return 1
  fi

  new_version="$(extract_script_version "$tmp_file")"
  if [[ -z "$new_version" ]]; then
    remove_file_and_error "$tmp_file" "读取新版本失败"
    return 1
  fi

  if ! is_version_newer "$new_version" "$SCRIPT_VERSION"; then
    remove_file_quietly "$tmp_file"
    UPDATE_AVAILABLE_VERSION=""
    log "已是最新版本"
    return 0
  fi

  run_or_error "升级临时文件权限设置失败: $tmp_file" chmod 755 "$tmp_file" || return 1
  if ! mv "$tmp_file" "$script_path"; then
    remove_file_and_error "$tmp_file" "升级写入失败: $script_path"
    return 1
  fi

  UPDATE_AVAILABLE_VERSION=""
  log "脚本已升级: $SCRIPT_VERSION -> $new_version, 重启中"
  save_cache_or_warn
  release_lock
  exec bash "$script_path"
  die "脚本重启失败: $script_path"
}

uninstall_script() {
  local script_path

  if [[ ! -x "$ACME_SH" ]]; then
    warn "未找到 ACME 客户端: $ACME_SH"
  elif ! "$ACME_SH" --uninstall; then
    warn "ACME 客户端卸载失败, 需手动处理"
  fi

  run_or_error "目录删除失败: $ACME_HOME" remove_dir_recursively_if_exists "$ACME_HOME" || return 1
  log "目录已清理: $ACME_HOME"

  run_or_error "缓存目录清理失败: $CACHE_HOME" remove_dir_recursively_if_exists "$CACHE_HOME" || return 1
  log "目录已清理: $CACHE_HOME"

  resolve_script_path_or_error script_path "脚本路径解析失败, 请手动删除脚本" || return 1

  if [[ -f "$script_path" ]]; then
    if [[ ! -w "$script_path" ]]; then
      err "脚本不可写, 请手动删除: $script_path"
      return 1
    fi
    if ! rm -f "$script_path"; then
      err "脚本删除失败, 请手动处理: $script_path"
      return 1
    fi
    log "脚本已删除: $script_path"
  fi

  release_lock
  exit 0
}

print_main_menu() {
  local menu_idx label

  printf '\n'
  printf '=== ACME 证书运维 %s ===\n' "$SCRIPT_VERSION"
  printf '%s\n' "$REPO_URL"
  printf '\n'
  for ((menu_idx = 1; menu_idx <= MENU_MAX_CHOICE; menu_idx++)); do
    label="${MENU_LABELS[$menu_idx]}"
    if [[ "${MENU_HANDLERS[$menu_idx]}" == "$MENU_UPDATE_SCRIPT_HANDLER" && -n "$UPDATE_AVAILABLE_VERSION" ]]; then
      label="${label} (可用版本: $UPDATE_AVAILABLE_VERSION)"
    fi
    printf ' %d. %s\n' "$menu_idx" "$label"
  done
  printf '\n'
}

validate_menu_config() {
  local menu_idx handler_name label_name

  if [[ "${#MENU_HANDLERS[@]}" -ne "${#MENU_LABELS[@]}" ]]; then
    die "菜单配置异常: handlers=${#MENU_HANDLERS[@]}, labels=${#MENU_LABELS[@]}"
  fi
  if ((MENU_MAX_CHOICE < 1)); then
    die "菜单配置异常: 无可用功能"
  fi

  for ((menu_idx = 1; menu_idx <= MENU_MAX_CHOICE; menu_idx++)); do
    handler_name="${MENU_HANDLERS[$menu_idx]}"
    label_name="${MENU_LABELS[$menu_idx]}"

    [[ -n "$handler_name" ]] || die "菜单配置异常: 空处理函数(index=$menu_idx)"
    [[ -n "$label_name" ]] || die "菜单配置异常: 空菜单文案(index=$menu_idx)"
    declare -F "$handler_name" >/dev/null || die "菜单配置异常: 处理函数不存在: $handler_name"
  done
}

run_menu_action() {
  local choice="$1"
  local choice_num

  if [[ "$choice" =~ ^[0-9]+$ ]]; then
    choice_num=$((10#$choice))
  else
    choice_num=0
  fi

  if ((choice_num >= 1 && choice_num <= MENU_MAX_CHOICE)); then
    "${MENU_HANDLERS[$choice_num]}"
    return
  fi

  err "选项无效: $choice (范围: 1-${MENU_MAX_CHOICE})"
  return 1
}

run_menu() {
  local choice

  while true; do
    print_main_menu

    read_prompt_value choice "请选择 [1-${MENU_MAX_CHOICE}]: "
    run_menu_action "$choice" || true
    save_cache_or_warn
  done
}

main() {
  if [[ "$#" -gt 0 ]]; then
    if [[ "$#" -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
      log "DNS API ACME 运维脚本"
      return 0
    fi
    die "不支持的参数: $*"
  fi

  require_root
  acquire_lock
  validate_menu_config
  load_cache_or_warn
  detect_os
  install_deps
  prompt_install_email_if_needed
  install_acme_sh
  check_script_update
  save_cache_or_warn
  run_menu
}

main "$@"
