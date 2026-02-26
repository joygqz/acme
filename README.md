# Acme

Linux 自动签发证书脚本（CentOS / Ubuntu / Debian），包含 `acme.sh` 安装。

## 使用

直接交互运行（推荐）：

```bash
sudo ./acme.sh
```

HTTP 模式（webroot）：

```bash
sudo ./acme.sh -d example.com -e admin@example.com -w /var/www/html -r "systemctl reload nginx"
```

HTTP 模式（standalone）：

```bash
sudo ./acme.sh -d api.example.com -e admin@example.com -s
```

DNS 模式（示例：Cloudflare）：

```bash
sudo ./acme.sh \
  -d example.com \
  -e admin@example.com \
  --dns dns_cf \
  --dns-cred CF_Key=xxxx \
  --dns-cred CF_Email=admin@example.com \
  -r "systemctl reload nginx"
```

## 参数

- `-d, --domain`: 域名（必填）
- `-e, --email`: 邮箱（必填）
- `--dns <provider>`: DNS 模式 provider（如 `dns_cf` / `dns_ali` / `dns_dp`）
- `--dns-cred <KEY=VALUE>`: DNS API 凭据，可重复传入
- `-w, --webroot`: webroot 模式目录
- `-s, --standalone`: 强制 standalone 模式
- `-k, --key-type`: `ec-256|ec-384|2048|3072|4096`（默认 `ec-256`）
- `-c, --ca`: `letsencrypt|zerossl|buypass`（默认 `letsencrypt`）
- `-o, --output`: 证书输出目录（默认 `/etc/ssl/<domain>`）
- `-r, --reload`: 证书安装后执行的重载命令
- `-i, --interactive`: 强制交互模式（不带参数默认进入）

## DNS 说明

- 默认验证方式是 DNS：即使只传 `-d/-e`，脚本也会进入交互让你补充 DNS provider 和凭据。
- DNS 模式下会忽略 `webroot/standalone` 参数。
- 你使用的 DNS 服务商所需变量名，请以 `acme.sh` 官方 DNS API 文档为准。
- 交互模式里，选择 `dns` 后可逐条输入 `KEY=VALUE`，回车空行结束。
- 脚本会校验域名、邮箱、DNS provider（需以 `dns_` 开头）和 DNS 凭据格式。

## 输出文件

默认在 `/etc/ssl/<domain>` 下生成：

- `<domain>.key`
- `fullchain.cer`
- `cert.cer`
- `ca.cer`
