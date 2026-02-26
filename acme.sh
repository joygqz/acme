#!/usr/bin/env bash

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

DOMAIN=""
EMAIL=""
WEBROOT=""
KEY_TYPE="ec-256"
CA_SERVER="letsencrypt"
OUTPUT_DIR=""
RELOAD_CMD=""
FORCE_STANDALONE=0
INTERACTIVE=0
DNS_PROVIDER=""
DNS_CREDENTIALS=()

log() {
  echo "[$(date '+%F %T')] $*"
}

err() {
  echo "[$(date '+%F %T')] ERROR: $*" >&2
}

is_valid_domain() {
  local d="$1"
  [[ "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

is_valid_email() {
  local e="$1"
  [[ "$e" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

is_valid_dns_provider() {
  local p="$1"
  [[ "$p" =~ ^dns_[A-Za-z0-9_]+$ ]]
}

require_option_value() {
  local opt="$1"
  local val="${2:-}"
  if [[ -z "$val" || "$val" == -* ]]; then
    err "$opt 需要一个值"
    usage
    exit 1
  fi
}

usage() {
  cat <<USAGE
用法:
  $SCRIPT_NAME -d <domain> -e <email> [选项]

必选参数:
  -d, --domain <domain>         主域名，如 example.com
  -e, --email <email>           ACME 账号邮箱

可选参数:
  --dns <provider>              使用 DNS 模式签发，如 dns_cf / dns_ali / dns_dp
  --dns-cred <KEY=VALUE>        DNS API 凭据，可重复，如 --dns-cred CF_Key=xxx
  -w, --webroot <path>          使用 webroot 模式签发（推荐线上站点）
  -s, --standalone              强制 standalone 模式（占用 80 端口）
  -k, --key-type <type>         密钥类型: ec-256|ec-384|2048|3072|4096，默认 ec-256
  -c, --ca <ca>                 CA: letsencrypt|zerossl|buypass，默认 letsencrypt
  -o, --output <dir>            证书输出目录，默认 /etc/ssl/<domain>
  -r, --reload <cmd>            安装证书后执行重载命令，如 "systemctl reload nginx"
  -i, --interactive             交互模式（不传参数时自动启用）
  -h, --help                    显示帮助

示例:
  $SCRIPT_NAME
  $SCRIPT_NAME -d example.com -e admin@example.com --dns dns_cf --dns-cred CF_Key=xxx --dns-cred CF_Email=admin@example.com
  $SCRIPT_NAME -d example.com -e admin@example.com -w /var/www/html -r "systemctl reload nginx"
  $SCRIPT_NAME -d api.example.com -e admin@example.com -s
USAGE
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "请使用 root 运行该脚本"
    exit 1
  fi
}

detect_os() {
  if [[ ! -f /etc/os-release ]]; then
    err "无法识别系统（缺少 /etc/os-release）"
    exit 1
  fi

  # shellcheck disable=SC1091
  source /etc/os-release

  OS_ID="${ID:-}"
  OS_LIKE="${ID_LIKE:-}"

  if [[ "$OS_ID" =~ (ubuntu|debian) ]] || [[ "$OS_LIKE" =~ (debian) ]]; then
    PKG_TYPE="apt"
    CRON_SERVICE="cron"
  elif [[ "$OS_ID" =~ (centos|rhel|rocky|almalinux|fedora) ]] || [[ "$OS_LIKE" =~ (rhel|fedora|centos) ]]; then
    if command -v dnf >/dev/null 2>&1; then
      PKG_TYPE="dnf"
    else
      PKG_TYPE="yum"
    fi
    CRON_SERVICE="crond"
  else
    err "暂不支持的系统: ID=${OS_ID}, ID_LIKE=${OS_LIKE}"
    exit 1
  fi

  log "检测到系统: ID=${OS_ID}, 使用包管理器: ${PKG_TYPE}"
}

install_deps() {
  log "安装基础依赖..."
  case "$PKG_TYPE" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y curl socat cron openssl ca-certificates
      ;;
    yum)
      yum install -y curl socat cronie openssl ca-certificates
      ;;
    dnf)
      dnf install -y curl socat cronie openssl ca-certificates
      ;;
  esac

  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "$CRON_SERVICE" || true
  fi
}

install_acme_sh() {
  if [[ -x /root/.acme.sh/acme.sh ]]; then
    log "检测到已安装 acme.sh，跳过安装"
  else
    log "安装 acme.sh..."
    curl https://get.acme.sh | sh -s email="$EMAIL"
  fi

  ACME_SH="/root/.acme.sh/acme.sh"
  if [[ ! -x "$ACME_SH" ]]; then
    err "acme.sh 安装失败，未找到: $ACME_SH"
    exit 1
  fi

  "$ACME_SH" --upgrade --auto-upgrade
  "$ACME_SH" --set-default-ca --server "$CA_SERVER"
}

build_issue_args() {
  ISSUE_ARGS=(--issue --keylength "$KEY_TYPE" --server "$CA_SERVER" -d "$DOMAIN")

  if [[ -n "$DNS_PROVIDER" ]]; then
    ISSUE_ARGS+=( --dns "$DNS_PROVIDER" )
    log "使用 DNS 模式签发: $DNS_PROVIDER"
  elif [[ -n "$WEBROOT" && "$FORCE_STANDALONE" -eq 0 ]]; then
    if [[ ! -d "$WEBROOT" ]]; then
      err "webroot 目录不存在: $WEBROOT"
      exit 1
    fi
    ISSUE_ARGS+=( -w "$WEBROOT" )
    log "使用 webroot 模式签发"
  else
    ISSUE_ARGS+=( --standalone )
    log "使用 standalone 模式签发（请确保 80 端口可用）"
  fi
}

apply_dns_credentials() {
  local item key value
  if [[ "${#DNS_CREDENTIALS[@]}" -eq 0 ]]; then
    return
  fi

  for item in "${DNS_CREDENTIALS[@]}"; do
    if [[ "$item" != *=* ]]; then
      err "DNS 凭据格式错误: $item (应为 KEY=VALUE)"
      exit 1
    fi
    key="${item%%=*}"
    value="${item#*=}"
    if [[ -z "$key" || -z "$value" ]]; then
      err "DNS 凭据格式错误: $item (KEY 或 VALUE 为空)"
      exit 1
    fi
    if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      err "DNS 凭据 KEY 非法: $key (应为环境变量名)"
      exit 1
    fi
    export "$key=$value"
  done

  log "已加载 ${#DNS_CREDENTIALS[@]} 个 DNS 凭据环境变量"
}

install_cert() {
  local cert_dir="$OUTPUT_DIR"
  mkdir -p "$cert_dir"

  INSTALL_ARGS=(
    --install-cert
    -d "$DOMAIN"
    --key-file "$cert_dir/$DOMAIN.key"
    --fullchain-file "$cert_dir/fullchain.cer"
    --cert-file "$cert_dir/cert.cer"
    --ca-file "$cert_dir/ca.cer"
  )

  if [[ -n "$RELOAD_CMD" ]]; then
    INSTALL_ARGS+=( --reloadcmd "$RELOAD_CMD" )
  fi

  "$ACME_SH" "${INSTALL_ARGS[@]}"

  chmod 600 "$cert_dir/$DOMAIN.key"
  chmod 644 "$cert_dir/fullchain.cer" "$cert_dir/cert.cer" "$cert_dir/ca.cer"

  log "证书已安装到: $cert_dir"
}

prompt_inputs() {
  local answer=""

  echo
  log "进入交互模式，请按提示输入参数"

  while [[ -z "$DOMAIN" ]]; do
    read -r -p "域名 (例如 example.com): " DOMAIN
    if [[ -n "$DOMAIN" ]] && ! is_valid_domain "$DOMAIN"; then
      err "域名格式不正确: $DOMAIN"
      DOMAIN=""
    fi
  done

  while [[ -z "$EMAIL" ]]; do
    read -r -p "邮箱 (例如 admin@example.com): " EMAIL
    if [[ -n "$EMAIL" ]] && ! is_valid_email "$EMAIL"; then
      err "邮箱格式不正确: $EMAIL"
      EMAIL=""
    fi
  done

  if [[ -z "$WEBROOT" && "$FORCE_STANDALONE" -eq 0 && -z "$DNS_PROVIDER" ]]; then
    read -r -p "验证方式 [1:dns(默认) 2:webroot 3:standalone]: " answer
    answer="${answer:-1}"
    case "$answer" in
      1)
        while [[ -z "$DNS_PROVIDER" ]]; do
          read -r -p "DNS Provider (如 dns_cf / dns_ali / dns_dp): " DNS_PROVIDER
          if [[ -n "$DNS_PROVIDER" ]] && ! is_valid_dns_provider "$DNS_PROVIDER"; then
            err "DNS Provider 格式不正确，应以 dns_ 开头，例如 dns_cf"
            DNS_PROVIDER=""
          fi
        done
        ;;
      2)
        while [[ -z "$WEBROOT" ]]; do
          read -r -p "webroot 路径: " WEBROOT
        done
        ;;
      3)
        FORCE_STANDALONE=1
        ;;
      *)
        err "无效选择，默认使用 dns"
        while [[ -z "$DNS_PROVIDER" ]]; do
          read -r -p "DNS Provider (如 dns_cf / dns_ali / dns_dp): " DNS_PROVIDER
          if [[ -n "$DNS_PROVIDER" ]] && ! is_valid_dns_provider "$DNS_PROVIDER"; then
            err "DNS Provider 格式不正确，应以 dns_ 开头，例如 dns_cf"
            DNS_PROVIDER=""
          fi
        done
        ;;
    esac
  fi

  if [[ -n "$DNS_PROVIDER" && "${#DNS_CREDENTIALS[@]}" -eq 0 ]]; then
    echo "请输入 DNS API 凭据，格式 KEY=VALUE，直接回车结束。"
    while true; do
      read -r -p "DNS 凭据: " answer
      if [[ -z "$answer" ]]; then
        break
      fi
      if [[ "$answer" != *=* ]]; then
        err "格式错误，请使用 KEY=VALUE"
        continue
      fi
      DNS_CREDENTIALS+=( "$answer" )
    done
  fi

  if [[ -z "$KEY_TYPE" ]]; then
    KEY_TYPE="ec-256"
  fi
  read -r -p "密钥类型 [ec-256/ec-384/2048/3072/4096] (默认: $KEY_TYPE): " answer
  KEY_TYPE="${answer:-$KEY_TYPE}"

  if [[ -z "$CA_SERVER" ]]; then
    CA_SERVER="letsencrypt"
  fi
  read -r -p "CA [letsencrypt/zerossl/buypass] (默认: $CA_SERVER): " answer
  CA_SERVER="${answer:-$CA_SERVER}"

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="/etc/ssl/$DOMAIN"
  fi
  read -r -p "证书输出目录 (默认: $OUTPUT_DIR): " answer
  OUTPUT_DIR="${answer:-$OUTPUT_DIR}"

  read -r -p "证书安装后重载命令(可留空): " answer
  if [[ -n "$answer" ]]; then
    RELOAD_CMD="$answer"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain)
        require_option_value "$1" "${2:-}"
        DOMAIN="${2:-}"
        shift 2
        ;;
      -e|--email)
        require_option_value "$1" "${2:-}"
        EMAIL="${2:-}"
        shift 2
        ;;
      -w|--webroot)
        require_option_value "$1" "${2:-}"
        WEBROOT="${2:-}"
        shift 2
        ;;
      -s|--standalone)
        FORCE_STANDALONE=1
        shift
        ;;
      --dns)
        require_option_value "$1" "${2:-}"
        DNS_PROVIDER="${2:-}"
        shift 2
        ;;
      --dns-cred)
        require_option_value "$1" "${2:-}"
        DNS_CREDENTIALS+=( "${2:-}" )
        shift 2
        ;;
      -k|--key-type)
        require_option_value "$1" "${2:-}"
        KEY_TYPE="${2:-}"
        shift 2
        ;;
      -c|--ca)
        require_option_value "$1" "${2:-}"
        CA_SERVER="${2:-}"
        shift 2
        ;;
      -o|--output)
        require_option_value "$1" "${2:-}"
        OUTPUT_DIR="${2:-}"
        shift 2
        ;;
      -r|--reload)
        require_option_value "$1" "${2:-}"
        RELOAD_CMD="${2:-}"
        shift 2
        ;;
      -i|--interactive)
        INTERACTIVE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        err "未知参数: $1"
        usage
        exit 1
        ;;
    esac
  done
}

validate_args() {
  if [[ -z "$DOMAIN" ]]; then
    err "必须指定 --domain"
    usage
    exit 1
  fi

  if [[ -z "$EMAIL" ]]; then
    err "必须指定 --email"
    usage
    exit 1
  fi

  if ! is_valid_domain "$DOMAIN"; then
    err "域名格式不正确: $DOMAIN"
    exit 1
  fi

  if ! is_valid_email "$EMAIL"; then
    err "邮箱格式不正确: $EMAIL"
    exit 1
  fi

  case "$KEY_TYPE" in
    ec-256|ec-384|2048|3072|4096) ;;
    *)
      err "不支持的 key type: $KEY_TYPE"
      exit 1
      ;;
  esac

  case "$CA_SERVER" in
    letsencrypt|zerossl|buypass) ;;
    *)
      err "不支持的 CA: $CA_SERVER"
      exit 1
      ;;
  esac

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="/etc/ssl/$DOMAIN"
  fi

  if [[ -n "$DNS_PROVIDER" ]]; then
    if ! is_valid_dns_provider "$DNS_PROVIDER"; then
      err "DNS Provider 格式不正确: $DNS_PROVIDER (应类似 dns_cf)"
      exit 1
    fi
    if [[ "$FORCE_STANDALONE" -eq 1 || -n "$WEBROOT" ]]; then
      log "已选择 DNS 模式，忽略 webroot/standalone 参数"
      FORCE_STANDALONE=0
      WEBROOT=""
    fi
  elif [[ -n "$WEBROOT" ]]; then
    if [[ ! -d "$WEBROOT" ]]; then
      err "webroot 目录不存在: $WEBROOT"
      exit 1
    fi
  fi
}

print_config_summary() {
  local mode="standalone"
  if [[ -n "$DNS_PROVIDER" ]]; then
    mode="dns:$DNS_PROVIDER"
  elif [[ -n "$WEBROOT" ]]; then
    mode="webroot:$WEBROOT"
  fi

  log "参数确认: domain=$DOMAIN, email=$EMAIL, mode=$mode, key_type=$KEY_TYPE, ca=$CA_SERVER, output=$OUTPUT_DIR"
  if [[ -n "$RELOAD_CMD" ]]; then
    log "参数确认: reload_cmd=$RELOAD_CMD"
  fi
}

main() {
  parse_args "$@"
  if [[ "$#" -eq 0 ]]; then
    INTERACTIVE=1
  fi
  if [[ -n "$DOMAIN" && -n "$EMAIL" && -z "$DNS_PROVIDER" && -z "$WEBROOT" && "$FORCE_STANDALONE" -eq 0 ]]; then
    # 默认验证方式为 DNS，需要交互获取 provider 与 DNS API 凭据
    INTERACTIVE=1
  fi
  if [[ "$INTERACTIVE" -eq 1 || -z "$DOMAIN" || -z "$EMAIL" ]]; then
    prompt_inputs
  fi
  validate_args
  print_config_summary
  require_root
  detect_os
  install_deps
  install_acme_sh

  apply_dns_credentials
  build_issue_args
  "$ACME_SH" "${ISSUE_ARGS[@]}"

  install_cert

  log "完成: 域名 $DOMAIN 证书申请与部署成功"
  log "续期由 acme.sh 自动任务处理，可手动测试: $ACME_SH --cron --home /root/.acme.sh"
}

main "$@"
