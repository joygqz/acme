#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly DEFAULT_KEY_TYPE="ec-256"
readonly DEFAULT_CA_SERVER="letsencrypt"
readonly DNS_PROVIDER="dns_cf"
readonly DEFAULT_ACME_HOME="/root/.acme.sh"
ACME_HOME="${ACME_HOME:-$DEFAULT_ACME_HOME}"
readonly ACME_HOME
readonly ACME_INSTALL_URL="https://get.acme.sh"
readonly REPO_URL="https://github.com/joygqz/acme"
readonly SCRIPT_RAW_URL="https://raw.githubusercontent.com/joygqz/acme/main/acme.sh"
readonly SCRIPT_VERSION="v1.0.0-beta.15"
readonly LOCK_FILE="/var/lock/joygqz-acme.lock"

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
CF_Key="${CF_Key:-}"
CF_Email="${CF_Email:-}"
CF_Token="${CF_Token:-}"
ISSUE_KEY_TYPE="$DEFAULT_KEY_TYPE"
ISSUE_CA_SERVER="$DEFAULT_CA_SERVER"
ISSUE_INCLUDE_WILDCARD="0"
ISSUE_FORCE_RENEW="0"
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
UPDATE_CHECKED_VERSION=""
UPDATE_CHECK_STATUS="unchecked"

curl_https() {
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location "$@"
}

resolve_script_path() {
  local source_path="${BASH_SOURCE[0]}"
  local source_dir=""
  local source_name=""

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

extract_version_from_script_file() {
  local file_path="$1"
  awk -F'"' '/^readonly SCRIPT_VERSION=/{print $2; exit}' "$file_path"
}

fetch_remote_script_version() {
  local remote_version=""

  if ! remote_version="$(
    curl_https --retry 2 --retry-delay 1 --connect-timeout 5 "$SCRIPT_RAW_URL" 2>/dev/null \
      | awk -F'"' '
          /^readonly SCRIPT_VERSION=/ {v=$2}
          END {
            if (v != "") {
              print v
            } else {
              exit 1
            }
          }
        '
  )"; then
    return 1
  fi

  [[ -n "$remote_version" ]] || return 1
  printf '%s\n' "$remote_version"
}

is_version_newer() {
  local candidate="$1"
  local baseline="$2"
  local highest=""

  if [[ "$candidate" == "$baseline" ]]; then
    return 1
  fi

  if ! command_exists sort; then
    [[ "$candidate" > "$baseline" ]]
    return
  fi

  highest="$(printf '%s\n%s\n' "$candidate" "$baseline" | sort -V | tail -n 1)"
  [[ "$highest" == "$candidate" ]]
}

check_script_update() {
  local remote_version=""

  if ! remote_version="$(fetch_remote_script_version)"; then
    UPDATE_AVAILABLE_VERSION=""
    UPDATE_CHECKED_VERSION=""
    UPDATE_CHECK_STATUS="failed"
    return
  fi

  UPDATE_CHECKED_VERSION="$remote_version"

  if ! is_version_newer "$remote_version" "$SCRIPT_VERSION"; then
    UPDATE_AVAILABLE_VERSION=""
    UPDATE_CHECK_STATUS="latest"
    return
  fi

  UPDATE_AVAILABLE_VERSION="$remote_version"
  UPDATE_CHECK_STATUS="available"
}

get_process_start_token() {
  local pid="$1"
  local token=""
  local lstart=""

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

remove_dir_recursively_if_exists() {
  local dir_path="$1"
  [[ -d "$dir_path" ]] || return
  rm -rf "$dir_path"
}

remove_file_and_error() {
  local file_path="$1"
  shift
  remove_file_quietly "$file_path"
  err "$*"
}

arm_dir_lock_cleanup() {
  local lock_dir="$1"
  local pid_file="$2"

  DIR_LOCK_DIR="$lock_dir"
  DIR_LOCK_PID_FILE="$pid_file"
  trap 'remove_file_quietly "$DIR_LOCK_PID_FILE"; remove_empty_dir_quietly "$DIR_LOCK_DIR"' EXIT
}

lock_conflict() {
  die "检测到脚本正在运行, 请稍后重试"
}

acquire_lock() {
  local lock_dir=""
  local pid_file=""
  local lock_pid=""
  local lock_start_token=""
  local current_start_token=""
  local self_start_token=""

  mkdir -p "$(dirname "$LOCK_FILE")"

  if command -v flock >/dev/null 2>&1; then
    exec {LOCK_FD}> "$LOCK_FILE"
    if ! flock -n "$LOCK_FD"; then
      lock_conflict
    fi
    return
  fi

  lock_dir="${LOCK_FILE}.d"
  pid_file="$lock_dir/pid"

  if mkdir "$lock_dir" 2>/dev/null; then
    self_start_token="$(get_process_start_token "$$")"
    printf '%s %s\n' "$$" "$self_start_token" > "$pid_file"
    arm_dir_lock_cleanup "$lock_dir" "$pid_file"
    return
  fi

  if [[ -f "$pid_file" ]]; then
    read -r lock_pid lock_start_token < "$pid_file" || true
    if [[ "$lock_pid" =~ ^[0-9]+$ ]] && kill -0 "$lock_pid" 2>/dev/null; then
      current_start_token="$(get_process_start_token "$lock_pid")"
      if [[ -z "$lock_start_token" ]]; then
        lock_conflict
      fi
      if [[ -z "$current_start_token" ]]; then
        lock_conflict
      fi
      if [[ "$lock_start_token" == "$current_start_token" ]]; then
        lock_conflict
      fi
    fi
  fi

  remove_file_quietly "$pid_file"
  if rmdir "$lock_dir" >/dev/null 2>&1 && mkdir "$lock_dir" 2>/dev/null; then
    self_start_token="$(get_process_start_token "$$")"
    printf '%s %s\n' "$$" "$self_start_token" > "$pid_file"
    arm_dir_lock_cleanup "$lock_dir" "$pid_file"
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
  COLOR_TITLE=$'\033[1;36m'
  COLOR_INDEX=$'\033[1;36m'
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
  err "警告: $*"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

get_missing_base_dependencies() {
  local -a missing=()
  local cmd=""

  for cmd in curl openssl crontab; do
    if ! command_exists "$cmd"; then
      missing+=( "$cmd" )
    fi
  done

  printf '%s\n' "${missing[*]}"
}

is_valid_domain() {
  local d="$1"
  [[ "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

is_valid_email() {
  local e="$1"
  [[ "$e" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

ensure_non_empty_input() {
  local target_var="$1"
  local prompt="$2"
  local empty_msg="$3"
  local hidden="${4:-0}"
  local value="${!target_var:-}"

  while true; do
    if [[ -z "$value" ]]; then
      if [[ "$hidden" == "1" ]]; then
        read -r -s -p "$prompt" value
        printf '\n'
      else
        read -r -p "$prompt" value
      fi
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
      read -r -p "$prompt" value
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
  [[ "${EUID}" -eq 0 ]] || die "请使用 root 用户运行脚本"
}

detect_os() {
  local os_id=""
  local os_like=""

  if [[ ! -f /etc/os-release ]]; then
    die "无法识别系统, 缺少 /etc/os-release"
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
    die "暂不支持该系统: ID=${os_id}, ID_LIKE=${os_like}"
  fi

}

has_ca_bundle() {
  [[ -r /etc/ssl/certs/ca-certificates.crt || -r /etc/pki/tls/certs/ca-bundle.crt ]]
}

has_systemd() {
  command_exists systemctl && [[ -d /run/systemd/system ]]
}

warn_service_action_failed() {
  local action="$1"
  warn "无法${action}服务 ${CRON_SERVICE}, 请手动检查"
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

needs_dependency_install() {
  local missing_deps=""

  missing_deps="$(get_missing_base_dependencies)"
  if [[ -n "$missing_deps" ]]; then
    return 0
  fi

  if ! has_ca_bundle; then
    return 0
  fi

  return 1
}

ensure_cron_service_running() {
  if has_systemd; then
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
    warn "未检测到 systemctl/service, 无法自动管理 ${CRON_SERVICE} 服务"
    return
  fi

  enable_non_systemd_service_autostart
  if ! service "$CRON_SERVICE" start >/dev/null 2>&1; then
    warn_service_action_failed "启动"
  fi
}

install_deps() {
  local missing_deps=""

  if ! needs_dependency_install; then
    ensure_cron_service_running
    return
  fi

  case "$PKG_TYPE" in
    apt)
      command_exists apt-get || die "缺少 apt-get 命令"
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y --no-install-recommends curl cron openssl ca-certificates
      ;;
    yum|dnf)
      command_exists "$PKG_TYPE" || die "缺少 ${PKG_TYPE} 命令"
      "$PKG_TYPE" install -y curl cronie openssl ca-certificates
      ;;
    *)
      die "未知包管理器: $PKG_TYPE"
      ;;
  esac

  missing_deps="$(get_missing_base_dependencies)"
  if [[ -n "$missing_deps" ]]; then
    die "依赖安装后仍缺少命令: $missing_deps"
  fi
  if ! has_ca_bundle; then
    die "依赖安装后仍缺少 CA 证书文件"
  fi

  ensure_cron_service_running
}

install_acme_sh() {
  if [[ ! -x "$ACME_SH" ]]; then
    curl_https --retry 3 --retry-delay 1 --connect-timeout 10 "$ACME_INSTALL_URL" \
      | sh -s "email=$EMAIL" --home "$ACME_HOME" --no-profile
  fi

  if [[ ! -x "$ACME_SH" ]]; then
    die "acme.sh 安装失败, 未找到文件: $ACME_SH"
  fi

  if [[ "${ACME_AUTO_UPGRADE:-0}" == "1" ]]; then
    "$ACME_SH" --upgrade --auto-upgrade
  fi
  ensure_default_ca
}

resolve_ca_server_url() {
  local ca_server="$1"

  case "$ca_server" in
    letsencrypt)
      printf '%s\n' "https://acme-v02.api.letsencrypt.org/directory"
      ;;
    zerossl)
      printf '%s\n' "https://acme.zerossl.com/v2/DV90"
      ;;
    buypass)
      printf '%s\n' "https://api.buypass.com/acme/directory"
      ;;
    *)
      printf '%s\n' "$ca_server"
      ;;
  esac
}

ensure_default_ca() {
  local account_conf="$ACME_HOME/account.conf"
  local current_ca=""
  local expected_ca=""

  if [[ -f "$account_conf" ]]; then
    current_ca="$(read_conf_value "$account_conf" "DEFAULT_ACME_SERVER")"
    current_ca="$(trim_outer_quotes "$current_ca")"
  fi

  expected_ca="$(resolve_ca_server_url "$DEFAULT_CA_SERVER")"

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

  ensure_valid_email_input EMAIL "首次安装, 请输入 ACME 邮箱: " "邮箱格式错误"
}

get_cert_conf_file() {
  local domain="$1"
  local preferred_variant="${2:-}"
  local variant=""
  local -a conf_candidates=()
  local conf_file=""

  case "$preferred_variant" in
    ecc)
      conf_candidates=( "ecc" "rsa" )
      ;;
    rsa)
      conf_candidates=( "rsa" "ecc" )
      ;;
    *)
      conf_candidates=( "ecc" "rsa" )
      ;;
  esac

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
  local suffix=""

  suffix="$(variant_dir_suffix "$variant")"
  printf '%s\n' "$ACME_HOME/${domain}${suffix}/${domain}.conf"
}

get_cert_dir_by_variant() {
  local domain="$1"
  local variant="$2"
  local suffix=""

  suffix="$(variant_dir_suffix "$variant")"
  printf '%s\n' "$ACME_HOME/${domain}${suffix}"
}

domain_has_existing_cert() {
  local domain="$1"
  get_cert_conf_file "$domain" >/dev/null 2>&1
}

cleanup_stale_domain_dirs() {
  local domain="$1"
  local ecc_conf=""
  local rsa_conf=""
  local ecc_dir=""
  local rsa_dir=""

  ecc_conf="$(get_cert_conf_path_by_variant "$domain" "ecc")"
  rsa_conf="$(get_cert_conf_path_by_variant "$domain" "rsa")"
  ecc_dir="$(get_cert_dir_by_variant "$domain" "ecc")"
  rsa_dir="$(get_cert_dir_by_variant "$domain" "rsa")"

  if [[ -d "$ecc_dir" && ! -f "$ecc_conf" ]]; then
    remove_dir_recursively_if_exists "$ecc_dir"
  fi
  if [[ -d "$rsa_dir" && ! -f "$rsa_conf" ]]; then
    remove_dir_recursively_if_exists "$rsa_dir"
  fi
}

cleanup_domain_variant_dir() {
  local domain="$1"
  local variant="$2"
  local cert_dir=""

  cert_dir="$(get_cert_dir_by_variant "$domain" "$variant")"
  remove_dir_recursively_if_exists "$cert_dir"
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
  local answer=""
  local ecc_conf=""
  local rsa_conf=""

  ecc_conf="$(get_cert_conf_path_by_variant "$domain" "ecc")"
  rsa_conf="$(get_cert_conf_path_by_variant "$domain" "rsa")"

  if [[ -f "$ecc_conf" ]]; then
    has_ecc="1"
  fi
  if [[ -f "$rsa_conf" ]]; then
    has_rsa="1"
  fi

  if [[ "$has_ecc" == "1" && "$has_rsa" == "1" ]]; then
    while true; do
      read -r -p "检测到 ECC/RSA, 请选择 [1] ECC [2] RSA: " answer
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
          err "选项无效, 请重新输入"
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

append_variant_flag() {
  local cert_variant="$1"

  if is_ecc_variant "$cert_variant"; then
    printf '%s\n' "--ecc"
  fi
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
  local answer=""
  local i=0

  while true; do
    read -r -p "$prompt" answer
    if [[ -z "$answer" ]]; then
      printf -v "$target_var" '%s' "$default_value"
      return
    fi

    i=0
    while [[ "$i" -lt "${#option_map[@]}" ]]; do
      if [[ "$answer" == "${option_map[$i]}" ]]; then
        printf -v "$target_var" '%s' "${option_map[$((i + 1))]}"
        return
      fi
      i=$((i + 2))
    done

    err "$invalid_msg"
  done
}

prompt_yes_no_default_no() {
  local target_var="$1"
  local prompt="$2"
  local answer=""
  local answer_lower=""

  while true; do
    read -r -p "$prompt" answer
    answer_lower="${answer,,}"
    case "$answer_lower" in
      ""|n|no)
        printf -v "$target_var" '%s' "0"
        return
        ;;
      y|yes)
        printf -v "$target_var" '%s' "1"
        return
        ;;
      *)
        err "请输入 y 或 n"
        ;;
    esac
  done
}

prompt_issue_options() {
  ISSUE_KEY_TYPE="$DEFAULT_KEY_TYPE"
  ISSUE_CA_SERVER="$DEFAULT_CA_SERVER"
  ISSUE_INCLUDE_WILDCARD="0"
  ISSUE_FORCE_RENEW="0"

  prompt_option_with_default \
    ISSUE_KEY_TYPE \
    "密钥类型 [1] ec-256 (默认), [2] ec-384, [3] rsa-2048, [4] rsa-4096: " \
    "ec-256" \
    "密钥类型选项无效, 请重新输入" \
    "1" "ec-256" \
    "2" "ec-384" \
    "3" "2048" \
    "4" "4096"

  prompt_option_with_default \
    ISSUE_CA_SERVER \
    "CA [1] letsencrypt (默认), [2] zerossl, [3] buypass: " \
    "letsencrypt" \
    "CA 选项无效, 请重新输入" \
    "1" "letsencrypt" \
    "2" "zerossl" \
    "3" "buypass"

  prompt_yes_no_default_no ISSUE_INCLUDE_WILDCARD "是否包含泛域名 *.$DOMAIN [y/N]: "
  prompt_yes_no_default_no ISSUE_FORCE_RENEW "是否强制重新签发 [y/N]: "
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

apply_dns_credentials() {
  if [[ -n "$CF_Token" ]]; then
    export CF_Token
    unset CF_Key CF_Email
    return
  fi

  export CF_Key CF_Email
  unset CF_Token
}

prompt_cf_token_credentials() {
  ensure_non_empty_input CF_Token "请输入 Cloudflare API Token (CF_Token): " "CF_Token 不能为空" "1"

  CF_Key=""
  CF_Email=""
}

prompt_cf_global_key_credentials() {
  ensure_valid_email_input CF_Email "请输入 Cloudflare 邮箱 (CF_Email): " "CF_Email 格式错误"
  ensure_non_empty_input CF_Key "请输入 Cloudflare Global API Key (CF_Key): " "CF_Key 不能为空" "1"

  CF_Token=""
}

prompt_cloudflare_credentials() {
  local auth_mode=""

  if [[ -n "$CF_Token" ]]; then
    prompt_cf_token_credentials
    return
  fi

  if [[ -n "$CF_Key" || -n "$CF_Email" ]]; then
    prompt_cf_global_key_credentials
    return
  fi

  prompt_option_with_default \
    auth_mode \
    "Cloudflare 鉴权 [1] API Token (推荐), [2] Global API Key: " \
    "token" \
    "鉴权选项无效, 请重新输入" \
    "1" "token" \
    "2" "key"

  if [[ "$auth_mode" == "token" ]]; then
    prompt_cf_token_credentials
    return
  fi

  prompt_cf_global_key_credentials
}

reset_create_inputs() {
  DOMAIN=""
  OUTPUT_DIR=""
  EMAIL=""
  CF_Key=""
  CF_Email=""
  CF_Token=""
}

install_cert_to_dir() {
  local cert_domain="$1"
  local cert_dir="$2"
  local cert_variant="$3"
  local variant_flag=""
  local -a install_args=(
    --install-cert
    --domain "$cert_domain"
    --key-file "$cert_dir/$cert_domain.key"
    --fullchain-file "$cert_dir/fullchain.cer"
    --cert-file "$cert_dir/cert.cer"
    --ca-file "$cert_dir/ca.cer"
  )

  [[ -n "$cert_variant" ]] || die "证书类型不能为空"

  mkdir -p "$cert_dir"
  chmod 755 "$cert_dir"

  variant_flag="$(append_variant_flag "$cert_variant")"
  if [[ -n "$variant_flag" ]]; then
    install_args+=( "$variant_flag" )
  fi

  "$ACME_SH" "${install_args[@]}"

  chmod 600 "$cert_dir/$cert_domain.key"
  chmod 644 "$cert_dir/fullchain.cer" "$cert_dir/cert.cer" "$cert_dir/ca.cer"
}

prompt_existing_cert_domain() {
  local target_var="$1"
  local prompt="$2"
  local raw_list=""
  local parsed_rows=""
  local domains=""
  local selected_domain=""

  raw_list="$(get_cert_list_raw)" || return 1
  parsed_rows="$(parse_cert_list_rows "$raw_list")"
  if [[ -z "$parsed_rows" ]]; then
    log "暂无证书"
    return 1
  fi

  print_cert_list "$raw_list" "$parsed_rows" || return 1
  domains="$(extract_cert_domains_from_rows "$parsed_rows")"

  while true; do
    selected_domain="$(prompt_domain_value "$prompt")"
    if printf '%s\n' "$domains" | grep -Fxq -- "$selected_domain"; then
      printf -v "$target_var" '%s' "$selected_domain"
      return 0
    fi
    err "证书不存在: $selected_domain"
  done
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
  local conf_file=""
  local cert_path=""
  local key_path=""

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

prompt_inputs() {
  local answer=""
  local email_prompt=""

  prompt_cloudflare_credentials

  if [[ -z "$EMAIL" ]]; then
    if [[ -n "$CF_Email" ]]; then
      EMAIL="$CF_Email"
      email_prompt="请输入 ACME 账号邮箱 (留空使用 CF_Email): "
    else
      email_prompt="请输入 ACME 账号邮箱 (例如: admin@example.com): "
    fi
  else
    email_prompt="请输入 ACME 账号邮箱 (留空使用: $EMAIL): "
  fi
  read -r -p "$email_prompt" answer
  EMAIL="${answer:-$EMAIL}"
  ensure_valid_email_input EMAIL "请输入 ACME 账号邮箱 (例如: admin@example.com): " "邮箱格式错误"
}

prompt_output_dir() {
  local answer=""
  local output_default=""

  while true; do
    output_default="${OUTPUT_DIR:-/etc/ssl/$DOMAIN}"
    read -r -p "输出目录 (默认: $output_default): " answer
    OUTPUT_DIR="${answer:-$output_default}"
    if [[ -n "$OUTPUT_DIR" ]]; then
      break
    fi
    err "输出目录不能为空"
  done
}

prompt_domain_value() {
  local prompt="$1"
  local value=""

  while true; do
    read -r -p "$prompt" value
    if [[ -z "$value" ]]; then
      err "域名不能为空"
      continue
    fi
    if ! is_valid_domain "$value"; then
      err "域名格式错误: $value"
      continue
    fi
    printf '%s\n' "$value"
    return
  done
}

get_cert_list_raw() {
  "$ACME_SH" --list --listraw
}

parse_cert_list_rows() {
  local raw_list="$1"
  printf '%s\n' "$raw_list" | awk -F'|' '
    NR == 1 { next }
    NF == 0 { next }
    {
      main_domain = $1
      key_length = $2
      san_domains = $3
      ca = $5
      created = $6
      renew = $7

      gsub(/^[[:space:]]+|[[:space:]]+$/, "", main_domain)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", key_length)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", san_domains)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", ca)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", created)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", renew)

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

extract_cert_domains_from_rows() {
  local parsed_rows="$1"
  printf '%s\n' "$parsed_rows" | awk -F'\t' '{print $1}'
}

print_cert_list() {
  local raw_list="$1"
  local parsed_rows="${2:-}"
  local border=""
  local row_variant=""
  local main_domain=""
  local key_length=""
  local san_domains=""
  local ca=""
  local created=""
  local renew=""
  local install_dir=""
  local main_domain_fmt=""
  local key_length_fmt=""
  local san_domains_fmt=""
  local ca_fmt=""
  local created_fmt=""
  local renew_fmt=""
  local install_dir_fmt=""

  if [[ -z "$parsed_rows" ]]; then
    parsed_rows="$(parse_cert_list_rows "$raw_list")"
  fi
  if [[ -z "$parsed_rows" ]]; then
    log "暂无证书"
    return 0
  fi

  border="+---------------------------+---------+---------------------------+-------------+----------------------+----------------------+----------------------------+"
  printf '\n'
  printf "%s证书列表%s\n" "$COLOR_TITLE" "$COLOR_RESET"
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
  local raw_list=""

  raw_list="$(get_cert_list_raw)" || return 1
  print_cert_list "$raw_list"
}

create_cert() {
  local cert_variant=""

  reset_create_inputs
  DOMAIN="$(prompt_domain_value "请输入域名 (例如: example.com): ")"

  if domain_has_existing_cert "$DOMAIN"; then
    err "域名已存在证书: $DOMAIN"
    return 1
  fi

  prompt_inputs
  prompt_issue_options
  cert_variant="$(key_type_to_variant "$ISSUE_KEY_TYPE")"

  cleanup_stale_domain_dirs "$DOMAIN"
  prompt_output_dir

  apply_dns_credentials
  if ! issue_cert; then
    cleanup_domain_variant_dir "$DOMAIN" "$cert_variant"
    err "证书申请失败"
    return 1
  fi
  install_cert_to_dir "$DOMAIN" "$OUTPUT_DIR" "$cert_variant"

  log "创建成功: $DOMAIN -> $OUTPUT_DIR"
}

update_cert() {
  local target_domain=""
  local cert_variant=""
  local cert_dir=""
  local current_install_dir=""
  local answer=""

  prompt_existing_cert_domain target_domain "请输入要更换安装目录的域名: " || return 1
  select_cert_variant_for_domain "$target_domain" cert_variant || return 1
  current_install_dir="$(get_cert_install_dir "$target_domain" "$cert_variant")"
  cert_dir="/etc/ssl/$target_domain"
  if [[ "$current_install_dir" != "-" ]]; then
    cert_dir="$current_install_dir"
  fi
  read -r -p "输出目录 (默认: $cert_dir): " answer
  cert_dir="${answer:-$cert_dir}"

  install_cert_to_dir "$target_domain" "$cert_dir" "$cert_variant"
  log "更换成功: $target_domain -> $cert_dir"
}

delete_cert() {
  local target_domain=""
  local cert_variant=""
  local variant_flag=""
  local acme_dir=""
  local -a remove_args=()

  prompt_existing_cert_domain target_domain "请输入待删除域名: " || return 1

  select_cert_variant_for_domain "$target_domain" cert_variant || return 1

  remove_args=( --remove --domain "$target_domain" )
  variant_flag="$(append_variant_flag "$cert_variant")"
  if [[ -n "$variant_flag" ]]; then
    remove_args+=( "$variant_flag" )
  fi
  "$ACME_SH" "${remove_args[@]}"

  acme_dir="$(get_cert_dir_by_variant "$target_domain" "$cert_variant")"
  remove_dir_recursively_if_exists "$acme_dir"

  log "删除成功: $target_domain"
}

update_script() {
  local script_path=""
  local script_dir=""
  local tmp_file=""
  local new_version=""

  script_path="$(resolve_script_path)" || {
    err "无法解析脚本路径"
    return 1
  }

  if [[ ! -f "$script_path" ]]; then
    err "脚本文件不存在: $script_path"
    return 1
  fi

  if [[ ! -w "$script_path" ]]; then
    err "脚本文件不可写: $script_path"
    return 1
  fi

  script_dir="$(dirname "$script_path")"
  if ! tmp_file="$(mktemp "${script_dir}/.acme.sh.update.XXXXXX")"; then
    err "创建临时文件失败"
    return 1
  fi

  if ! curl_https --retry 3 --retry-delay 1 --connect-timeout 10 "$SCRIPT_RAW_URL" -o "$tmp_file"; then
    remove_file_and_error "$tmp_file" "下载更新失败"
    return 1
  fi

  if ! grep -q '^readonly SCRIPT_VERSION=' "$tmp_file"; then
    remove_file_and_error "$tmp_file" "更新文件校验失败"
    return 1
  fi

  if ! bash -n "$tmp_file"; then
    remove_file_and_error "$tmp_file" "更新文件语法校验失败"
    return 1
  fi

  new_version="$(extract_version_from_script_file "$tmp_file")"
  if [[ -z "$new_version" ]]; then
    remove_file_and_error "$tmp_file" "无法读取新版本号"
    return 1
  fi

  if ! is_version_newer "$new_version" "$SCRIPT_VERSION"; then
    remove_file_quietly "$tmp_file"
    UPDATE_AVAILABLE_VERSION=""
    UPDATE_CHECKED_VERSION="$new_version"
    UPDATE_CHECK_STATUS="latest"
    if [[ "$new_version" == "$SCRIPT_VERSION" ]]; then
      log "已是最新版本: $SCRIPT_VERSION"
    else
      log "远端版本较旧, 跳过更新: $new_version (当前: $SCRIPT_VERSION)"
    fi
    return 0
  fi

  chmod 755 "$tmp_file"
  if ! mv "$tmp_file" "$script_path"; then
    remove_file_and_error "$tmp_file" "写入更新失败: $script_path"
    return 1
  fi

  UPDATE_AVAILABLE_VERSION=""
  UPDATE_CHECKED_VERSION=""
  UPDATE_CHECK_STATUS="unchecked"
  log "更新成功: $SCRIPT_VERSION -> $new_version, 正在重启脚本"
  release_lock
  exec bash "$script_path"
  die "脚本重启失败: $script_path"
}

print_main_menu() {
  local update_label="更新脚本"

  case "$UPDATE_CHECK_STATUS" in
    available)
      update_label="更新脚本 (最新: $UPDATE_AVAILABLE_VERSION)"
      ;;
    latest)
      if [[ -n "$UPDATE_CHECKED_VERSION" ]]; then
        update_label="更新脚本 (已最新: $UPDATE_CHECKED_VERSION)"
      else
        update_label="更新脚本 (已最新)"
      fi
      ;;
    failed)
      update_label="更新脚本 (检查失败)"
      ;;
  esac

  printf '\n'
  printf '%s=== ACME 证书管理 %s ===%s\n' "$COLOR_TITLE" "$SCRIPT_VERSION" "$COLOR_RESET"
  printf '%s\n' "$REPO_URL"
  printf '\n'
  printf ' %s1.%s 查看证书\n' "$COLOR_INDEX" "$COLOR_RESET"
  printf ' %s2.%s 创建证书\n' "$COLOR_INDEX" "$COLOR_RESET"
  printf ' %s3.%s 更换安装目录\n' "$COLOR_INDEX" "$COLOR_RESET"
  printf ' %s4.%s 删除证书\n' "$COLOR_INDEX" "$COLOR_RESET"
  printf ' %s5.%s %s\n' "$COLOR_INDEX" "$COLOR_RESET" "$update_label"
  printf ' %s0.%s 退出\n' "$COLOR_INDEX" "$COLOR_RESET"
  printf '\n'
}

run_menu_action() {
  "$@" || true
}

print_usage() {
  cat <<USAGE
用法:
  bash acme.sh

说明:
  交互式管理 Cloudflare DNS 的 ACME 证书
  启动自动检查脚本更新, 菜单 [5] 可执行更新
USAGE
}

run_menu() {
  local choice=""

  while true; do
    print_main_menu

    read -r -p "请输入选择 [0-5]: " choice
    case "$choice" in
      1)
        run_menu_action list_certs
        ;;
      2)
        run_menu_action create_cert
        ;;
      3)
        run_menu_action update_cert
        ;;
      4)
        run_menu_action delete_cert
        ;;
      5)
        if ! update_script; then
          return
        fi
        ;;
      0)
        return
        ;;
      *)
        err "无效选项: $choice"
        ;;
    esac
  done
}

main() {
  if [[ "$#" -gt 0 ]]; then
    if [[ "$#" -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
      print_usage
      return 0
    fi
    die "不支持参数: $*"
  fi

  require_root
  acquire_lock
  init_colors
  detect_os
  install_deps
  prompt_install_email_if_needed
  install_acme_sh
  check_script_update
  run_menu
}

main "$@"
