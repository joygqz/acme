# ACME CertOps

交互式 ACME 证书管理脚本

## DNS Provider 参考

https://github.com/acmesh-official/acme.sh/wiki/dnsapi

## 快速开始

```bash
curl -fsSL https://raw.githubusercontent.com/joygqz/acme/main/acmec.sh -o acmec.sh && chmod +x acmec.sh && ./acmec.sh
```

## 后续运行

```bash
./acmec.sh
```

## Cloudflare 凭据示例

```bash
DNS Provider (默认: dns_cf): dns_cf

# 账号邮箱 + Global API Key
DNS 凭据 (KEY=VALUE, 空格分隔): CF_Email=xxx CF_Key=xxx

# 或

# API Token
DNS 凭据 (KEY=VALUE, 空格分隔): CF_Token=xxx
```
