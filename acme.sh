#!/usr/bin/env bash

set -euo pipefail

readonly KEY_TYPE="ec-256"
readonly CA_SERVER="letsencrypt"
readonly DNS_PROVIDER="dns_cf"
readonly ACME_HOME="/root/.acme.sh"
readonly ACME_INSTALL_URL="https://get.acme.sh"
readonly REPO_URL="https://github.com/joygqz/acme"

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
RELOAD_CMD="${RELOAD_CMD:-}"
CF_Key="${CF_Key:-}"
CF_Email="${CF_Email:-}"
PKG_TYPE=""
CRON_SERVICE=""
ACME_SH="$ACME_HOME/acme.sh"
COLOR_RESET=""
COLOR_TITLE=""
COLOR_INDEX=""

init_colors() {
  if [[ "${NO_COLOR:-}" == "1" || "${NO_COLOR:-}" == "true" ]]; then
    return
  fi
  COLOR_RESET=$'\033[0m'
  COLOR_TITLE=$'\033[1;36m'
  COLOR_INDEX=$'\033[1;36m'
}

log() {
  echo "$*"
}

err() {
  echo "ERROR: $*" >&2
}

die() {
  err "$*"
  exit 1
}

ensure_not_empty() {
  local field="$1"
  local value="$2"
  [[ -n "$value" ]] || die "$field 不能为空."
}

ensure_valid_domain() {
  local value="$1"
  ensure_not_empty "域名" "$value"
  is_valid_domain "$value" || die "域名格式错误: $value"
}

ensure_valid_email() {
  local field="$1"
  local value="$2"
  ensure_not_empty "$field" "$value"
  is_valid_email "$value" || die "$field 格式错误: $value"
}

is_valid_domain() {
  local d="$1"
  [[ "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

is_valid_email() {
  local e="$1"
  [[ "$e" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "请使用 root 用户运行脚本."
}

detect_os() {
  local os_id=""
  local os_like=""

  if [[ ! -f /etc/os-release ]]; then
    die "无法识别系统, 缺少 /etc/os-release."
  fi

  # shellcheck disable=SC1091
  source /etc/os-release

  os_id="${ID:-}"
  os_like="${ID_LIKE:-}"

  if [[ "$os_id" =~ (ubuntu|debian) ]] || [[ "$os_like" =~ (debian) ]]; then
    PKG_TYPE="apt"
    CRON_SERVICE="cron"
  elif [[ "$os_id" =~ (centos|rhel|rocky|almalinux|fedora) ]] || [[ "$os_like" =~ (rhel|fedora|centos) ]]; then
    if command -v dnf >/dev/null 2>&1; then
      PKG_TYPE="dnf"
    else
      PKG_TYPE="yum"
    fi
    CRON_SERVICE="crond"
  else
    die "暂不支持该系统: ID=${os_id}, ID_LIKE=${os_like}."
  fi

}

install_deps() {
  case "$PKG_TYPE" in
    apt)
      command -v apt-get >/dev/null 2>&1 || die "缺少 apt-get 命令."
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y curl socat cron openssl ca-certificates
      ;;
    yum)
      command -v yum >/dev/null 2>&1 || die "缺少 yum 命令."
      yum install -y curl socat cronie openssl ca-certificates
      ;;
    dnf)
      command -v dnf >/dev/null 2>&1 || die "缺少 dnf 命令."
      dnf install -y curl socat cronie openssl ca-certificates
      ;;
    *)
      die "未知包管理器: $PKG_TYPE."
      ;;
  esac

  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "$CRON_SERVICE" || true
  fi
}

install_acme_sh() {
  if [[ ! -x "$ACME_SH" ]]; then
    log "正在安装 acme.sh..."
    curl -fsSL "$ACME_INSTALL_URL" | sh -s email="$EMAIL"
  fi

  if [[ ! -x "$ACME_SH" ]]; then
    die "acme.sh 安装失败, 未找到文件: $ACME_SH."
  fi

  if ! "$ACME_SH" --upgrade --auto-upgrade >/dev/null 2>&1; then
    err "acme.sh 自动升级失败, 将继续使用当前版本."
  fi
  "$ACME_SH" --set-default-ca --server "$CA_SERVER" >/dev/null 2>&1 || die "设置默认 CA 失败."
}

prompt_install_email_if_needed() {
  if [[ -x "$ACME_SH" ]]; then
    return
  fi

  if [[ -z "$EMAIL" && -n "$CF_Email" ]]; then
    EMAIL="$CF_Email"
  fi

  while [[ -z "$EMAIL" ]]; do
    read -r -p "首次安装需要邮箱, 请输入 ACME 账号邮箱: " EMAIL
    if [[ -n "$EMAIL" ]] && ! is_valid_email "$EMAIL"; then
      err "邮箱格式错误: $EMAIL"
      EMAIL=""
    fi
  done
}

run_acme_cmd() {
  local action="$1"
  shift
  local output=""

  if ! output="$("$ACME_SH" "$@" 2>&1)"; then
    err "$action 失败."
    [[ -n "$output" ]] && err "$output"
    return 1
  fi
}

issue_cert() {
  local -a issue_args=(
    --issue
    --keylength "$KEY_TYPE"
    --server "$CA_SERVER"
    -d "$DOMAIN"
    --dns "$DNS_PROVIDER"
  )
  log "正在申请证书..."
  run_acme_cmd "证书申请" "${issue_args[@]}"
}

apply_dns_credentials() {
  export CF_Key CF_Email
}

install_cert_to_dir() {
  local cert_domain="$1"
  local cert_dir="$2"
  local -a install_args=(
    --install-cert
    -d "$cert_domain"
    --key-file "$cert_dir/$cert_domain.key"
    --fullchain-file "$cert_dir/fullchain.cer"
    --cert-file "$cert_dir/cert.cer"
    --ca-file "$cert_dir/ca.cer"
  )

  mkdir -p "$cert_dir"

  if [[ -n "$RELOAD_CMD" ]]; then
    install_args+=( --reloadcmd "$RELOAD_CMD" )
  fi

  run_acme_cmd "证书安装" "${install_args[@]}"

  chmod 600 "$cert_dir/$cert_domain.key"
  chmod 644 "$cert_dir/fullchain.cer" "$cert_dir/cert.cer" "$cert_dir/ca.cer"
}

prompt_inputs() {
  local answer=""
  local output_default=""
  local email_prompt=""

  while [[ -z "$DOMAIN" ]]; do
    read -r -p "请输入域名 (例如: example.com): " DOMAIN
    if [[ -n "$DOMAIN" ]] && ! is_valid_domain "$DOMAIN"; then
      err "域名格式错误: $DOMAIN"
      DOMAIN=""
    fi
  done

  while [[ -z "$CF_Email" ]]; do
    read -r -p "请输入 Cloudflare 邮箱 (CF_Email): " CF_Email
    if [[ -n "$CF_Email" ]] && ! is_valid_email "$CF_Email"; then
      err "CF_Email 格式错误: $CF_Email"
      CF_Email=""
    fi
  done

  while [[ -z "$CF_Key" ]]; do
    read -r -p "请输入 Cloudflare API Key (CF_Key): " CF_Key
    if [[ -z "$CF_Key" ]]; then
      err "CF_Key 不能为空."
    fi
  done

  if [[ -z "$EMAIL" ]]; then
    EMAIL="$CF_Email"
    email_prompt="请输入 ACME 账号邮箱 (留空使用 CF_Email): "
  else
    email_prompt="请输入 ACME 账号邮箱 (留空使用: $EMAIL): "
  fi
  read -r -p "$email_prompt" answer
  EMAIL="${answer:-$EMAIL}"
  while ! is_valid_email "$EMAIL"; do
    err "邮箱格式错误: $EMAIL"
    read -r -p "请输入 ACME 账号邮箱 (例如: admin@example.com): " EMAIL
  done

  output_default="${OUTPUT_DIR:-/etc/ssl/$DOMAIN}"
  read -r -p "请输入证书输出目录 (默认: $output_default): " answer
  OUTPUT_DIR="${answer:-$output_default}"
}

validate_inputs() {
  ensure_valid_domain "$DOMAIN"
  ensure_valid_email "邮箱" "$EMAIL"
  ensure_valid_email "CF_Email" "$CF_Email"
  ensure_not_empty "CF_Key" "$CF_Key"
  ensure_not_empty "证书输出目录" "$OUTPUT_DIR"
}

prompt_domain_value() {
  local prompt="$1"
  local value=""

  while true; do
    read -r -p "$prompt" value
    if [[ -z "$value" ]]; then
      err "域名不能为空."
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
  local raw_list=""

  if ! raw_list="$("$ACME_SH" --list 2>&1)"; then
    err "读取证书列表失败."
    [[ -n "$raw_list" ]] && err "$raw_list"
    return 1
  fi

  printf '%s\n' "$raw_list"
}

extract_cert_domains() {
  local raw_list="$1"
  printf '%s\n' "$raw_list" | awk 'NR>1 && NF>0 {print $1}'
}

print_cert_list() {
  local raw_list="$1"
  local data_count=0
  local border=""

  data_count="$(printf '%s\n' "$raw_list" | awk 'NR>1 && NF>0 {count++} END {print count+0}')"
  if [[ "$data_count" -eq 0 ]]; then
    log "当前没有证书."
    return 0
  fi

  border="+----+---------------------------+---------+---------------------------+-------------+----------------------+----------------------+"
  printf '\n'
  printf "%s证书列表%s\n" "$COLOR_TITLE" "$COLOR_RESET"
  printf '\n'
  printf '%s\n' "$border"
  printf "| %-2s | %-25s | %-7s | %-25s | %-11s | %-20s | %-20s |\n" \
    "No" "Domain" "Key" "SAN" "CA" "Created" "Renew"
  printf '%s\n' "$border"

  printf '%s\n' "$raw_list" | awk -v c="$COLOR_INDEX" -v r="$COLOR_RESET" '
    function trunc(s, w) {
      if (length(s) <= w) return s
      return substr(s, 1, w - 3) "..."
    }
    NR == 1 { next }
    NF > 0 {
      n++
      main_domain = $1
      key_length = $2
      san_domains = $3
      ca = (NF >= 4 ? $4 : "-")
      created = (NF >= 5 ? $5 : "-")
      renew = (NF >= 6 ? $6 : "-")

      gsub(/"/, "", key_length)
      if (san_domains == "no" || san_domains == "") san_domains = "-"
      if (ca == "") ca = "-"
      if (created == "") created = "-"
      if (renew == "") renew = "-"

      printf "| %s%2d%s | %-25s | %-7s | %-25s | %-11s | %-20s | %-20s |\n",
        c, n, r,
        trunc(main_domain, 25),
        trunc(key_length, 7),
        trunc(san_domains, 25),
        trunc(ca, 11),
        trunc(created, 20),
        trunc(renew, 20)
    }
  '
  printf '%s\n' "$border"
  log "证书总数: $data_count."
  printf '\n'
}

list_certs() {
  local raw_list=""

  raw_list="$(get_cert_list_raw)" || return 1
  print_cert_list "$raw_list"
}

create_cert() {
  DOMAIN=""
  OUTPUT_DIR=""

  prompt_inputs
  validate_inputs

  apply_dns_credentials
  issue_cert
  install_cert_to_dir "$DOMAIN" "$OUTPUT_DIR"

  log "申请成功: $DOMAIN -> $OUTPUT_DIR, 自动续期已启用."
}

update_cert() {
  local target_domain=""
  local cert_dir=""
  local answer=""

  target_domain="$(prompt_domain_value "请输入要更新的域名: ")"
  cert_dir="/etc/ssl/$target_domain"
  read -r -p "请输入证书输出目录 (默认: $cert_dir): " answer
  cert_dir="${answer:-$cert_dir}"

  if [[ -n "$CF_Key" && -n "$CF_Email" ]]; then
    apply_dns_credentials
  fi

  log "正在更新证书..."
  run_acme_cmd "证书更新" --renew -d "$target_domain" --force

  install_cert_to_dir "$target_domain" "$cert_dir"
  log "更新成功: $target_domain -> $cert_dir."
}

delete_cert() {
  local target_domain=""
  local selector=""
  local raw_list=""
  local domains=""
  local answer=""
  local cert_dir=""
  local acme_dir_rsa=""
  local acme_dir_ecc=""
  local local_dir_deleted=0

  raw_list="$(get_cert_list_raw)" || return 1
  print_cert_list "$raw_list" || return 1
  domains="$(extract_cert_domains "$raw_list")"
  if [[ -z "$domains" ]]; then
    return 0
  fi

  while true; do
    read -r -p "请输入待删除的序号或域名 (0 返回): " selector
    if [[ -z "$selector" ]]; then
      err "请输入序号或域名, 或输入 0 返回."
      continue
    fi

    if [[ "$selector" == "0" ]]; then
      log "已取消删除."
      return 0
    fi

    if [[ "$selector" =~ ^[0-9]+$ ]]; then
      target_domain="$(printf '%s\n' "$domains" | sed -n "${selector}p")"
      if [[ -z "$target_domain" ]]; then
        err "序号无效: $selector."
        continue
      fi
      break
    fi

    if printf '%s\n' "$domains" | grep -Fxq -- "$selector"; then
      target_domain="$selector"
      break
    fi

    err "未找到域名: $selector."
  done

  run_acme_cmd "证书删除" --remove -d "$target_domain"

  acme_dir_rsa="$ACME_HOME/$target_domain"
  acme_dir_ecc="$ACME_HOME/${target_domain}_ecc"
  if [[ -d "$acme_dir_rsa" ]]; then
    rm -rf "$acme_dir_rsa"
  fi
  if [[ -d "$acme_dir_ecc" ]]; then
    rm -rf "$acme_dir_ecc"
  fi

  cert_dir="/etc/ssl/$target_domain"
  if [[ -d "$cert_dir" ]]; then
    read -r -p "是否删除本地证书目录 $cert_dir? [y/N]: " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
      rm -rf "$cert_dir"
      local_dir_deleted=1
    fi
  fi

  if [[ "$local_dir_deleted" -eq 1 ]]; then
    log "删除成功: $target_domain, 本地目录已删除: $cert_dir."
  else
    log "删除成功: $target_domain."
  fi
}

print_main_menu() {
  cat <<MENU

${COLOR_TITLE}=== ACME 证书管理 ===${COLOR_RESET}
${REPO_URL}

 ${COLOR_INDEX}1.${COLOR_RESET} 查看证书
 ${COLOR_INDEX}2.${COLOR_RESET} 创建证书
 ${COLOR_INDEX}3.${COLOR_RESET} 更新证书
 ${COLOR_INDEX}4.${COLOR_RESET} 删除证书
 ${COLOR_INDEX}0.${COLOR_RESET} 退出

MENU
}

run_menu() {
  local choice=""

  while true; do
    print_main_menu

    read -r -p "请输入选择 [0-4]: " choice
    case "$choice" in
      1)
        list_certs
        ;;
      2)
        create_cert
        ;;
      3)
        update_cert
        ;;
      4)
        delete_cert
        ;;
      0)
        log "已退出."
        return
        ;;
      *)
        err "无效选项: $choice."
        ;;
    esac
  done
}

main() {
  if [[ "$#" -gt 0 ]]; then
    exit 1
  fi

  require_root
  init_colors
  detect_os
  install_deps
  prompt_install_email_if_needed
  install_acme_sh
  run_menu
}

main "$@"
