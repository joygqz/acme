#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly DEFAULT_KEY_TYPE="ec-256"
readonly DEFAULT_CA_SERVER="letsencrypt"
readonly DNS_PROVIDER="dns_cf"
readonly DEFAULT_ACME_HOME="/root/.acme.sh"
readonly ACME_HOME="${ACME_HOME:-$DEFAULT_ACME_HOME}"
readonly ACME_INSTALL_URL="https://get.acme.sh"
readonly REPO_URL="https://github.com/joygqz/acme"
readonly SCRIPT_RAW_URL="https://raw.githubusercontent.com/joygqz/acme/main/acmec.sh"
readonly SCRIPT_VERSION="v1.0.0"
readonly DEFAULT_CACHE_HOME="/root/.acmec.sh"
readonly CACHE_HOME="${ACME_CACHE_HOME:-$DEFAULT_CACHE_HOME}"
readonly CACHE_PREFS_FILE="$CACHE_HOME/preferences.tsv"
readonly CACHE_SECRETS_FILE="$CACHE_HOME/secrets.tsv"
readonly CACHE_SCHEMA_VERSION="1"
readonly CACHE_WRAPPER_VERSION_KEY="CACHE_WRAPPER_VERSION"
readonly UPDATE_CACHE_TTL_SECONDS="21600"
readonly LOCK_FILE="/var/lock/acmec.sh.lock"
readonly CURL_RETRY_COUNT="3"
readonly CURL_RETRY_DELAY="1"
readonly SCRIPT_CHECK_CONNECT_TIMEOUT="5"
readonly SCRIPT_CHECK_MAX_TIME="15"
readonly SCRIPT_UPDATE_CONNECT_TIMEOUT="10"
readonly SCRIPT_UPDATE_MAX_TIME="25"
readonly INSTALL_CONNECT_TIMEOUT="10"
readonly -a MENU_HANDLERS=( "" "list_certs" "create_cert" "update_cert" "delete_cert" "update_script" "uninstall_script" )
readonly -a MENU_LABELS=( "" "证书清单" "签发证书" "更新证书路径" "删除证书" "升级脚本" "卸载工具" )
readonly MENU_UPDATE_SCRIPT_HANDLER="update_script"
readonly MENU_MAX_CHOICE="$(( ${#MENU_HANDLERS[@]} - 1 ))"

readonly ENV_HAS_EMAIL="${EMAIL+1}"
readonly ENV_HAS_CF_KEY="${CF_Key+1}"
readonly ENV_HAS_CF_EMAIL="${CF_Email+1}"
readonly ENV_HAS_CF_TOKEN="${CF_Token+1}"
readonly ENV_HAS_ISSUE_KEY_TYPE="${ISSUE_KEY_TYPE+1}"
readonly ENV_HAS_ISSUE_CA_SERVER="${ISSUE_CA_SERVER+1}"
readonly ENV_HAS_ISSUE_INCLUDE_WILDCARD="${ISSUE_INCLUDE_WILDCARD+1}"
readonly ENV_HAS_ISSUE_FORCE_RENEW="${ISSUE_FORCE_RENEW+1}"
readonly ENV_HAS_CF_AUTH_MODE="${CF_AUTH_MODE+1}"
readonly ENV_HAS_DEPLOY_BASE_DIR="${DEPLOY_BASE_DIR+1}"
readonly ENV_HAS_CACHE_PERSIST_CREDENTIALS="${CACHE_PERSIST_CREDENTIALS+1}"

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
CF_Key="${CF_Key:-}"
CF_Email="${CF_Email:-}"
CF_Token="${CF_Token:-}"
ISSUE_KEY_TYPE="${ISSUE_KEY_TYPE:-$DEFAULT_KEY_TYPE}"
ISSUE_CA_SERVER="${ISSUE_CA_SERVER:-$DEFAULT_CA_SERVER}"
ISSUE_INCLUDE_WILDCARD="${ISSUE_INCLUDE_WILDCARD:-0}"
ISSUE_FORCE_RENEW="${ISSUE_FORCE_RENEW:-0}"
CF_AUTH_MODE="${CF_AUTH_MODE:-token}"
DEPLOY_BASE_DIR="${DEPLOY_BASE_DIR:-/etc/ssl}"
CACHE_PERSIST_CREDENTIALS="${CACHE_PERSIST_CREDENTIALS:-1}"
UPDATE_CACHE_LAST_CHECK_TS=""
UPDATE_CACHE_BASELINE_VERSION=""
UPDATE_CACHE_NEWER_VERSION=""
PKG_TYPE=""
CRON_SERVICE=""
ACME_SH="$ACME_HOME/acme.sh"
COLOR_RESET=""
COLOR_TITLE=""
COLOR_INDEX=""
COLOR_ERROR_TEXT=""
LOCK_FD=""
DIR_LOCK_DIR=""
DIR_LOCK_PID_FILE=""
UPDATE_AVAILABLE_VERSION=""

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
  local regex='^v?([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

  [[ "$version" =~ $regex ]] || return 1
  printf '%s\t%s\t%s\t%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[5]}"
}

is_prerelease_newer() {
  local candidate_pre="$1"
  local baseline_pre="$2"
  local -a candidate_parts=()
  local -a baseline_parts=()
  local part_idx=0
  local candidate_id baseline_id
  IFS='.' read -r -a candidate_parts <<< "$candidate_pre"
  IFS='.' read -r -a baseline_parts <<< "$baseline_pre"

  while true; do
    candidate_id="${candidate_parts[$part_idx]:-}"
    baseline_id="${baseline_parts[$part_idx]:-}"

    if [[ -z "$candidate_id" && -z "$baseline_id" ]]; then
      return 1
    fi
    if [[ -z "$candidate_id" ]]; then
      return 1
    fi
    if [[ -z "$baseline_id" ]]; then
      return 0
    fi

    if [[ "$candidate_id" =~ ^[0-9]+$ && "$baseline_id" =~ ^[0-9]+$ ]]; then
      if ((10#$candidate_id > 10#$baseline_id)); then
        return 0
      fi
      if ((10#$candidate_id < 10#$baseline_id)); then
        return 1
      fi
    elif [[ "$candidate_id" =~ ^[0-9]+$ ]]; then
      return 1
    elif [[ "$baseline_id" =~ ^[0-9]+$ ]]; then
      return 0
    else
      if [[ "$candidate_id" > "$baseline_id" ]]; then
        return 0
      fi
      if [[ "$candidate_id" < "$baseline_id" ]]; then
        return 1
      fi
    fi

    part_idx=$((part_idx + 1))
  done
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
  local candidate_major candidate_minor candidate_patch candidate_pre
  local baseline_major baseline_minor baseline_patch baseline_pre
  [[ "$candidate" != "$baseline" ]] || return 1
  IFS=$'\t' read -r candidate_major candidate_minor candidate_patch candidate_pre <<< "$(parse_semver "$candidate")" || return 1
  IFS=$'\t' read -r baseline_major baseline_minor baseline_patch baseline_pre <<< "$(parse_semver "$baseline")" || return 1

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

  if [[ -z "$candidate_pre" && -n "$baseline_pre" ]]; then
    return 0
  fi
  if [[ -n "$candidate_pre" && -z "$baseline_pre" ]]; then
    return 1
  fi
  if [[ -z "$candidate_pre" && -z "$baseline_pre" ]]; then
    return 1
  fi

  is_prerelease_newer "$candidate_pre" "$baseline_pre"
}

check_script_update() {
  local remote_version now_ts
  UPDATE_AVAILABLE_VERSION=""

  now_ts="$(current_epoch_seconds)"
  if is_update_cache_fresh "$now_ts"; then
    UPDATE_AVAILABLE_VERSION="$UPDATE_CACHE_NEWER_VERSION"
    return
  fi

  if ! remote_version="$(fetch_remote_script_version)"; then
    return
  fi

  if is_version_newer "$remote_version" "$SCRIPT_VERSION"; then
    UPDATE_AVAILABLE_VERSION="$remote_version"
  fi

  UPDATE_CACHE_LAST_CHECK_TS="$now_ts"
  UPDATE_CACHE_BASELINE_VERSION="$SCRIPT_VERSION"
  UPDATE_CACHE_NEWER_VERSION="$UPDATE_AVAILABLE_VERSION"
}

get_process_start_token() {
  local pid="$1"
  local token lstart
  if [[ -r "/proc/$pid/stat" ]]; then
    token="$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || true)"
    if [[ -n "$token" ]]; then
      printf '%s\n' "$token"
      return
    fi
  fi

  lstart="$(ps -o lstart= -p "$pid" 2>/dev/null | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]][[:space:]]*/ /g')"
  if [[ -n "$lstart" ]]; then
    printf '%s\n' "$lstart" | cksum | awk '{print $1}'
    return
  fi

  printf '\n'
}

remove_file_quietly() {
  local file_path="$1"
  [[ -n "$file_path" ]] || return
  rm -f "$file_path" >/dev/null 2>&1 || true
}

remove_empty_dir_quietly() {
  local dir_path="$1"
  [[ -n "$dir_path" ]] || return
  rmdir "$dir_path" >/dev/null 2>&1 || true
}

is_unsafe_delete_target() {
  local dir_path="$1"
  case "$dir_path" in
    ""|"/"|"."|"..")
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
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "CF_AUTH_MODE" "CF_AUTH_MODE" "$ENV_HAS_CF_AUTH_MODE"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "DEPLOY_BASE_DIR" "DEPLOY_BASE_DIR" "$ENV_HAS_DEPLOY_BASE_DIR"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "CACHE_PERSIST_CREDENTIALS" "CACHE_PERSIST_CREDENTIALS" "$ENV_HAS_CACHE_PERSIST_CREDENTIALS"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "UPDATE_CACHE_LAST_CHECK_TS" "UPDATE_CACHE_LAST_CHECK_TS"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "UPDATE_CACHE_BASELINE_VERSION" "UPDATE_CACHE_BASELINE_VERSION"
  load_cache_entry_into_var "$CACHE_PREFS_FILE" "UPDATE_CACHE_NEWER_VERSION" "UPDATE_CACHE_NEWER_VERSION"
}

load_cached_secrets() {
  load_cache_entry_into_var "$CACHE_SECRETS_FILE" "CF_Token" "CF_Token" "$ENV_HAS_CF_TOKEN"
  load_cache_entry_into_var "$CACHE_SECRETS_FILE" "CF_Key" "CF_Key" "$ENV_HAS_CF_KEY"
  load_cache_entry_into_var "$CACHE_SECRETS_FILE" "CF_Email" "CF_Email" "$ENV_HAS_CF_EMAIL"
}

reset_persistent_cache_files() {
  remove_file_quietly "$CACHE_PREFS_FILE"
  remove_file_quietly "$CACHE_SECRETS_FILE"
}

ensure_cache_schema_compatible() {
  local cached_schema="" cached_wrapper_version=""

  [[ -f "$CACHE_PREFS_FILE" ]] || return 0
  cached_schema="$(read_cache_entry "$CACHE_PREFS_FILE" "CACHE_SCHEMA_VERSION" 2>/dev/null || true)"

  if [[ "$cached_schema" != "$CACHE_SCHEMA_VERSION" ]]; then
    reset_persistent_cache_files
    warn "缓存结构变更，已重置缓存"
    return 0
  fi

  cached_wrapper_version="$(read_cache_entry "$CACHE_PREFS_FILE" "$CACHE_WRAPPER_VERSION_KEY" 2>/dev/null || true)"
  if [[ -n "$cached_wrapper_version" && "$cached_wrapper_version" == "$SCRIPT_VERSION" ]]; then
    return 0
  fi

  reset_persistent_cache_files
  warn "脚本版本变更，已重置缓存"
}

normalize_cached_settings() {
  normalize_issue_options

  case "$CF_AUTH_MODE" in
    token|key) ;;
    *) CF_AUTH_MODE="token" ;;
  esac

  case "$CACHE_PERSIST_CREDENTIALS" in
    0|1) ;;
    *) CACHE_PERSIST_CREDENTIALS="1" ;;
  esac

  [[ -n "$DEPLOY_BASE_DIR" ]] || DEPLOY_BASE_DIR="/etc/ssl"

  case "$UPDATE_CACHE_LAST_CHECK_TS" in
    ''|*[!0-9]*)
      UPDATE_CACHE_LAST_CHECK_TS=""
      ;;
  esac
}

load_persistent_cache() {
  ensure_cache_home || return 1
  ensure_cache_schema_compatible
  load_cached_preferences

  if [[ "$CACHE_PERSIST_CREDENTIALS" == "1" ]]; then
    load_cached_secrets
  else
    CF_Token=""
    CF_Key=""
    CF_Email=""
  fi

  normalize_cached_settings
}

save_cached_preferences() {
  write_cache_entries "$CACHE_PREFS_FILE" \
    "CACHE_SCHEMA_VERSION" "$CACHE_SCHEMA_VERSION" \
    "$CACHE_WRAPPER_VERSION_KEY" "$SCRIPT_VERSION" \
    "EMAIL" "$EMAIL" \
    "ISSUE_KEY_TYPE" "$ISSUE_KEY_TYPE" \
    "ISSUE_CA_SERVER" "$ISSUE_CA_SERVER" \
    "ISSUE_INCLUDE_WILDCARD" "$ISSUE_INCLUDE_WILDCARD" \
    "ISSUE_FORCE_RENEW" "$ISSUE_FORCE_RENEW" \
    "CF_AUTH_MODE" "$CF_AUTH_MODE" \
    "DEPLOY_BASE_DIR" "$DEPLOY_BASE_DIR" \
    "CACHE_PERSIST_CREDENTIALS" "$CACHE_PERSIST_CREDENTIALS" \
    "UPDATE_CACHE_LAST_CHECK_TS" "$UPDATE_CACHE_LAST_CHECK_TS" \
    "UPDATE_CACHE_BASELINE_VERSION" "$UPDATE_CACHE_BASELINE_VERSION" \
    "UPDATE_CACHE_NEWER_VERSION" "$UPDATE_CACHE_NEWER_VERSION"
}

save_cached_secrets() {
  if [[ "$CACHE_PERSIST_CREDENTIALS" != "1" ]]; then
    remove_file_quietly "$CACHE_SECRETS_FILE"
    return 0
  fi

  write_cache_entries "$CACHE_SECRETS_FILE" \
    "CF_Token" "${CF_Token:-}" \
    "CF_Key" "${CF_Key:-}" \
    "CF_Email" "${CF_Email:-}"
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

current_epoch_seconds() {
  date +%s
}

is_update_cache_fresh() {
  local now_ts="$1"

  [[ -n "$UPDATE_CACHE_LAST_CHECK_TS" ]] || return 1
  [[ "$UPDATE_CACHE_BASELINE_VERSION" == "$SCRIPT_VERSION" ]] || return 1
  ((now_ts >= UPDATE_CACHE_LAST_CHECK_TS)) || return 1
  (((now_ts - UPDATE_CACHE_LAST_CHECK_TS) < UPDATE_CACHE_TTL_SECONDS))
}

write_dir_lock_state() {
  local lock_dir="$1"
  local pid_file="$2"
  local self_start_token
  self_start_token="$(get_process_start_token "$$")"
  printf '%s %s\n' "$$" "$self_start_token" > "$pid_file"
  DIR_LOCK_DIR="$lock_dir"
  DIR_LOCK_PID_FILE="$pid_file"
  trap 'remove_file_quietly "$DIR_LOCK_PID_FILE"; remove_empty_dir_quietly "$DIR_LOCK_DIR"' EXIT
}

lock_conflict() {
  die "已有实例运行中"
}

acquire_lock() {
  local lock_dir pid_file
  local lock_pid lock_start_token current_start_token
  mkdir -p "$(dirname "$LOCK_FILE")"

  if command_exists flock; then
    exec {LOCK_FD}> "$LOCK_FILE"
    if ! flock -n "$LOCK_FD"; then
      lock_conflict
    fi
    return
  fi

  lock_dir="${LOCK_FILE}.d"
  pid_file="$lock_dir/pid"

  if mkdir "$lock_dir" 2>/dev/null; then
    write_dir_lock_state "$lock_dir" "$pid_file"
    return
  fi

  if [[ -f "$pid_file" ]]; then
    read -r lock_pid lock_start_token < "$pid_file" || true
    if [[ "$lock_pid" =~ ^[0-9]+$ ]] && kill -0 "$lock_pid" 2>/dev/null; then
      current_start_token="$(get_process_start_token "$lock_pid")"
      if [[ -z "$lock_start_token" || -z "$current_start_token" || "$lock_start_token" == "$current_start_token" ]]; then
        lock_conflict
      fi
    fi
  fi

  remove_file_quietly "$pid_file"
  if rmdir "$lock_dir" >/dev/null 2>&1 && mkdir "$lock_dir" 2>/dev/null; then
    write_dir_lock_state "$lock_dir" "$pid_file"
    return
  fi

  lock_conflict
}

release_lock() {
  if [[ -n "$LOCK_FD" ]]; then
    flock -u "$LOCK_FD" >/dev/null 2>&1 || true
    exec {LOCK_FD}>&- || true
    LOCK_FD=""
  fi

  if [[ -n "$DIR_LOCK_PID_FILE" ]]; then
    remove_file_quietly "$DIR_LOCK_PID_FILE"
    DIR_LOCK_PID_FILE=""
  fi

  if [[ -n "$DIR_LOCK_DIR" ]]; then
    remove_empty_dir_quietly "$DIR_LOCK_DIR"
    DIR_LOCK_DIR=""
  fi

  trap - EXIT
}

init_colors() {
  if [[ "${NO_COLOR:-}" == "1" || "${NO_COLOR:-}" == "true" ]]; then
    return
  fi
  COLOR_RESET=$'\033[0m'
  COLOR_TITLE=$'\033[1;94m'
  COLOR_INDEX=$'\033[1;94m'
  COLOR_ERROR_TEXT=$'\033[0;31m'
}

log() {
  printf '%s\n' "$*"
}

err() {
  if [[ -n "$COLOR_ERROR_TEXT" ]]; then
    printf '%s\n' "${COLOR_ERROR_TEXT}$*${COLOR_RESET}" >&2
    return
  fi
  printf '%s\n' "$*" >&2
}

die() {
  err "$*"
  exit 1
}

warn() {
  err "WARN: $*"
}

log_no_cert_records() {
  log "未检测到证书记录"
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
  local hidden="${3:-0}"
  local input_value=""
  local read_status=0

  if [[ "$hidden" == "1" ]]; then
    IFS= read -r -s -p "$prompt" input_value || read_status=$?
    printf '\n'
  else
    IFS= read -r -p "$prompt" input_value || read_status=$?
  fi

  if ((read_status != 0)); then
    die "输入中断"
  fi

  printf -v "$target_var" '%s' "$input_value"
}

ensure_non_empty_input() {
  local target_var="$1"
  local prompt="$2"
  local empty_msg="$3"
  local hidden="${4:-0}"
  local value="${!target_var:-}"

  while true; do
    if [[ -z "$value" ]]; then
      read_prompt_value value "$prompt" "$hidden"
    fi

    if [[ -n "$value" ]]; then
      printf -v "$target_var" '%s' "$value"
      return
    fi

    err "$empty_msg"
    value=""
  done
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
  warn "${CRON_SERVICE} ${action}失败，需手动处理"
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
    warn "未检测到 systemctl/service，跳过 ${CRON_SERVICE} 自动管理"
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

  if [[ -z "$EMAIL" && -n "$CF_Email" ]]; then
    EMAIL="$CF_Email"
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
      read_prompt_value answer "检测到 ECC/RSA，请选择 [1] ECC [2] RSA: "
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

prompt_cf_token_credentials() {
  ensure_non_empty_input CF_Token "请输入 Cloudflare API Token (CF_Token): " "CF_Token 不能为空" "1"

  CF_Key=""
  CF_Email=""
}

prompt_cf_global_key_credentials() {
  ensure_valid_email_input CF_Email "请输入 Cloudflare 邮箱 (CF_Email): " "CF_Email 格式无效"
  ensure_non_empty_input CF_Key "请输入 Cloudflare Global API Key (CF_Key): " "CF_Key 不能为空" "1"

  CF_Token=""
}

prompt_cloudflare_credentials_by_mode() {
  local auth_mode="$1"
  CF_AUTH_MODE="$auth_mode"
  if [[ "$auth_mode" == "token" ]]; then
    prompt_cf_token_credentials
    return
  fi
  prompt_cf_global_key_credentials
}

prompt_cloudflare_credentials() {
  local auth_mode="$CF_AUTH_MODE"

  case "$auth_mode" in
    token|key) ;;
    *)
      if [[ -n "$CF_Token" ]]; then
        auth_mode="token"
      elif [[ -n "$CF_Key" || -n "$CF_Email" ]]; then
        auth_mode="key"
      else
        auth_mode="token"
      fi
      ;;
  esac

  if [[ "$auth_mode" == "token" && -n "$CF_Token" ]]; then
    prompt_cloudflare_credentials_by_mode "token"
    return
  fi

  if [[ "$auth_mode" == "key" && -n "$CF_Key" && -n "$CF_Email" ]]; then
    prompt_cloudflare_credentials_by_mode "key"
    return
  fi

  prompt_option_with_default \
    auth_mode \
    "Cloudflare 认证方式 [1] API Token [2] Global API Key (默认: $auth_mode): " \
    "$auth_mode" \
    "认证方式无效" \
    "1" "token" \
    "2" "key"

  prompt_cloudflare_credentials_by_mode "$auth_mode"
}

apply_cloudflare_credentials_env() {
  CF_Token="${CF_Token:-}"
  CF_Key="${CF_Key:-}"
  CF_Email="${CF_Email:-}"

  if [[ -n "$CF_Token" ]]; then
    CF_Key=""
    CF_Email=""
  else
    CF_Token=""
  fi

  export CF_Token CF_Key CF_Email
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

fetch_cert_list_raw() {
  "$ACME_SH" --list --listraw
}

prompt_existing_cert_domain() {
  local target_var="$1"
  local prompt="$2"
  local raw_list parsed_rows selected_domain
  raw_list="$(fetch_cert_list_raw)" || return 1
  parsed_rows="$(parse_cert_list_rows "$raw_list")"
  if [[ -z "$parsed_rows" ]]; then
    log_no_cert_records
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
    log_no_cert_records
    return 0
  fi

  border="+---------------------------+---------+---------------------------+-------------+----------------------+----------------------+----------------------------+"
  printf '\n'
  printf "%s证书清单%s\n" "$COLOR_TITLE" "$COLOR_RESET"
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

    printf "| %s%-25s%s | %-7s | %-25s | %-11s | %-20s | %-20s | %-26s |\n" \
      "$COLOR_INDEX" "$main_domain_fmt" "$COLOR_RESET" \
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
  raw_list="$(fetch_cert_list_raw)" || return 1
  print_cert_list "$raw_list"
}

create_cert() {
  local cert_variant cert_dir default_output_dir
  DOMAIN="$(prompt_domain_value "请输入域名 (示例: example.com): ")"

  if cert_domain_exists "$DOMAIN"; then
    err "证书已存在: $DOMAIN"
    return 1
  fi

  prompt_cloudflare_credentials
  prompt_issue_options
  cert_variant="$(key_type_to_variant "$ISSUE_KEY_TYPE")"

  cleanup_stale_domain_dirs "$DOMAIN"
  default_output_dir="$(default_output_dir_for_domain "$DOMAIN")"
  prompt_output_dir_with_default OUTPUT_DIR "$default_output_dir"
  apply_cloudflare_credentials_env
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
    cert_dir="/etc/ssl/$target_domain"
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
    UPDATE_CACHE_LAST_CHECK_TS="$(current_epoch_seconds)"
    UPDATE_CACHE_BASELINE_VERSION="$SCRIPT_VERSION"
    UPDATE_CACHE_NEWER_VERSION=""
    log "已是最新版本"
    return 0
  fi

  run_or_error "升级临时文件权限设置失败: $tmp_file" chmod 755 "$tmp_file" || return 1
  if ! mv "$tmp_file" "$script_path"; then
    remove_file_and_error "$tmp_file" "升级写入失败: $script_path"
    return 1
  fi

  UPDATE_AVAILABLE_VERSION=""
  log "脚本已升级: $SCRIPT_VERSION -> $new_version，重启中"
  save_cache_or_warn
  release_lock
  exec bash "$script_path"
  die "脚本重启失败: $script_path"
}

uninstall_script() {
  local confirmed remove_acme_home
  local script_path

  prompt_yes_no_with_default confirmed "确认卸载 ACME 客户端并删除当前脚本? [y/N]: " "0"
  if [[ "$confirmed" != "1" ]]; then
    return 0
  fi

  if [[ ! -x "$ACME_SH" ]]; then
    warn "未找到 ACME 客户端: $ACME_SH"
  elif ! "$ACME_SH" --uninstall; then
    warn "ACME 客户端卸载失败，需手动处理"
  fi

  prompt_yes_no_with_default remove_acme_home "删除 ACME_HOME 目录 ($ACME_HOME) [y/N]: " "0"
  run_or_error "缓存目录清理失败: $CACHE_HOME" remove_dir_recursively_if_exists "$CACHE_HOME" || return 1
  log "缓存已清理: $CACHE_HOME"

  if [[ "$remove_acme_home" == "1" ]]; then
    run_or_error "目录删除失败: $ACME_HOME" remove_dir_recursively_if_exists "$ACME_HOME" || return 1
    log "ACME_HOME 已删除: $ACME_HOME"
  fi

  resolve_script_path_or_error script_path "脚本路径解析失败，请手动删除脚本" || return 1

  if [[ -f "$script_path" ]]; then
    if [[ ! -w "$script_path" ]]; then
      err "脚本不可写，请手动删除: $script_path"
      return 1
    fi
    if ! rm -f "$script_path"; then
      err "脚本删除失败，请手动处理: $script_path"
      return 1
    fi
    log "脚本已删除: $script_path"
  else
    log "脚本文件不存在: $script_path"
  fi

  release_lock
  exit 0
}

print_main_menu() {
  local menu_idx label

  printf '\n'
  printf '%s=== ACME 证书运维 %s ===%s\n' "$COLOR_TITLE" "$SCRIPT_VERSION" "$COLOR_RESET"
  printf '%s\n' "$REPO_URL"
  printf '\n'
  for ((menu_idx = 1; menu_idx <= MENU_MAX_CHOICE; menu_idx++)); do
    label="${MENU_LABELS[$menu_idx]}"
    if [[ "${MENU_HANDLERS[$menu_idx]}" == "$MENU_UPDATE_SCRIPT_HANDLER" && -n "$UPDATE_AVAILABLE_VERSION" ]]; then
      label="${label} (可用版本: $UPDATE_AVAILABLE_VERSION)"
    fi
    printf ' %s%d.%s %s\n' "$COLOR_INDEX" "$menu_idx" "$COLOR_RESET" "$label"
  done
  printf '\n'
}

print_usage() {
  cat <<USAGE
Cloudflare DNS ACME 运维脚本
USAGE
}

validate_menu_config() {
  local menu_idx handler_name label_name
  local has_update_handler="0"

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

    if [[ "$handler_name" == "$MENU_UPDATE_SCRIPT_HANDLER" ]]; then
      has_update_handler="1"
    fi
  done
  [[ "$has_update_handler" == "1" ]] || die "菜单配置异常: 缺少升级功能入口"
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
      print_usage
      return 0
    fi
    die "不支持的参数: $*"
  fi

  require_root
  acquire_lock
  init_colors
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
