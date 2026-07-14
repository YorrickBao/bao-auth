# bao-auth

一个自托管、单二进制的 Web 版 TOTP 验证器（Google Authenticator / Authy 的自部署替代）。

后端 Go + 前端原生 HTML/JS（通过 `embed` 打包进二进制），数据加密存于本地 SQLite。
**原始密钥绝不离开服务器**——浏览器只拿到后端实时算出的验证码。

## 目录

- [快速开始](#快速开始) — 3 分钟本地跑起来
- [部署到服务器](#部署到服务器) — 交叉编译 / systemd / nginx / 升级
- [配置](#配置) — 命令行参数
- [功能特性](#功能特性)
- [安全模型](#安全模型)
- [升级](#升级) — 替换二进制 + 自动回滚
- [API](#api)
- [项目结构](#项目结构)

---

## 快速开始

```bash
go build -o bao-auth .
./bao-auth
```

打开 `http://127.0.0.1:3000`，首次访问设置主密码即可开始使用。

添加账户的三种方式（按便捷度排序）：
1. **扫描二维码**：摄像头实时扫描 / 上传图片 / 截图后 Ctrl+V 粘贴
2. **粘贴链接**：复制 `otpauth://` URI 直接粘贴解析
3. **手动输入**：逐字段填写 secret、issuer 等

## 部署到服务器

### 1. 交叉编译

纯 Go（SQLite 用 `modernc.org/sqlite`，无 CGO），交叉编译零障碍：

```bash
# 一次构建全部平台
./build.sh
# 产物在 dist/，如 dist/bao-auth-linux-amd64

# 或只编译目标平台
./build.sh linux/amd64
```

上传到服务器：

```bash
scp dist/bao-auth-linux-amd64 user@server:/opt/bao-auth/bao-auth.new
```

### 2. systemd 服务（含安全加固）

**创建专用用户**（不要用 root 运行，遵循最小权限原则）：

```bash
sudo useradd -r -s /usr/sbin/nologin baoauth
sudo mkdir -p /opt/bao-auth/data
sudo chown -R baoauth:baoauth /opt/bao-auth
sudo chmod 700 /opt/bao-auth/data
```

**创建服务文件** `/etc/systemd/system/bao-auth.service`：

```ini
[Unit]
Description=bao-auth
After=network.target

[Service]
ExecStart=/opt/bao-auth/bao-auth --addr 127.0.0.1:3000 --data /opt/bao-auth/data
WorkingDirectory=/opt/bao-auth
Restart=on-failure
User=baoauth
Group=baoauth

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/bao-auth/data
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bao-auth
```

### 3. nginx 反向代理

建议用 nginx 反代并配置 HTTPS。两种形态：

**独立子域名（推荐，最省心）**：

```nginx
server {
    server_name otp.example.com;
    listen 443 ssl http2;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**路径前缀（与其他服务共用域名）**：

启动时加 `--prefix`，nginx 原样转发（`proxy_pass` 末尾**不要**加 `/`）：

```bash
./bao-auth --addr 127.0.0.1:3000 --prefix /otp
```

```nginx
location /otp/ {
    proxy_pass http://127.0.0.1:3000;   # 末尾无 /，保留前缀转发
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

访问 `https://example.com/otp/`。`--prefix` 会同时作用于 API 路由、静态资源、前端请求基址，确保子路径下所有链接正确。

## 配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--addr` | `127.0.0.1:3000` | 监听地址 |
| `--data` | `./data` | 数据目录（SQLite 文件存放处） |
| `--prefix` | `""`（根路径） | URL 路径前缀，用于子路径反代部署（如 `/otp`） |

## 功能特性

- 🔐 **单二进制部署**：前端、后端、数据库驱动全编译进一个 ~10MB 可执行文件，零外部依赖
- 📷 **多种扫码方式**：摄像头实时扫描（优先背面）、上传图片、截图粘贴
- ⏱️ **实时倒计时**：本地每秒刷新圆环，到周期边界自动拉取新码
- 🔎 **搜索 / 编辑 / 删除**
- 💾 **导入 / 导出备份**
- 🛡️ **加密存储**：主密码 scrypt 派生 KEK，secret 用 AES-256-GCM 加密；KEK 只存内存，重启即锁
- 🔑 **原始密钥不外泄**：接口只返回实时 TOTP 码，绝不回传 secret（仅主动导出时例外）
- 🚦 **登录限速**：连续失败自动冷却，缓解暴力破解
- 🌗 **深色 / 浅色自适应**

## 安全模型

| 资产 | 存储位置 | 保护方式 |
|------|----------|----------|
| 主密码（bcrypt 哈希） | SQLite | bcrypt（仅用于校验登录） |
| KEK 派生盐 | SQLite | — |
| secret 密文 | SQLite | AES-256-GCM，密钥=主密码派生的 KEK |
| KEK（密钥加密密钥） | **仅内存** | 登录时从主密码实时派生，不落盘；服务器重启即失效 |
| 会话 | 浏览器 sessionStorage | JWT（HS256，签名密钥每次启动随机） |

**重要**：
- **主密码无法找回**。遗忘则所有已存 secret 永久不可恢复。
- 建议定期用"导出"功能生成明文 JSON 备份，离线妥善保管。
- 生产环境务必通过 HTTPS 反代访问，避免主密码与验证码在传输中被窃听。
- 共享环境请勿将服务的**唯一** 2FA 凭据只存于此处——前端也会在添加时提醒。

## 升级

升级只需替换二进制文件并重启。**不能直接覆盖正在运行的二进制**（Linux 会报 `Text file busy`），需先 rename 再替换。

### 一键发布（推荐）

本地一条命令完成编译 + 上传 + 远程升级：

```bash
./release.sh -s user@server                           # 最简（默认 linux/amd64）
./release.sh -s user@server -t linux/arm64            # 指定平台
./release.sh -s user@server -o "-p 2222"              # 附加 SSH 参数
```

选项：
- `-s` SSH 目标（`user@server`），必填
- `-t` 目标平台，默认 `linux/amd64`
- `-d` 远程目录，默认 `/opt/bao-auth`
- `-o` 额外 SSH 参数，如 `"-i ~/.ssh/key -p 2222"`

`release.sh` 会调用 `build.sh` 编译 → `scp` 上传 → 远程执行 `upgrade.sh`。
其中 `upgrade.sh` 带**自动回滚**：rename 旧二进制 → 替换 → 重启 → 检查状态，启动失败则恢复旧版本。

### 手动升级

```bash
# 本地编译 + 上传
./build.sh linux/amd64
scp dist/bao-auth-linux-amd64 user@server:/opt/bao-auth/bao-auth.new

# 服务器上执行升级
ssh user@server 'cd /opt/bao-auth && sudo ./upgrade.sh bao-auth.new'
```

> 升级**不丢数据**——SQLite 数据库在 `data/` 目录，替换二进制不碰它。服务器重启后需重新登录（KEK 从内存清除，这是设计使然）。

## API

所有 `/api/*` 接口（除 `status`/`setup`/`login`）需 `Authorization: Bearer <token>` 头。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/status` | 是否已初始化 |
| POST | `/api/setup` | 首次设置主密码 |
| POST | `/api/login` | 登录 |
| POST | `/api/logout` | 登出（清除内存 KEK） |
| GET | `/api/accounts` | 列表（返回实时码，不含 secret） |
| POST | `/api/accounts` | 新增 |
| PUT | `/api/accounts/:id` | 编辑 |
| DELETE | `/api/accounts/:id` | 删除 |
| POST | `/api/parse-uri` | 解析 otpauth URI |
| GET | `/api/export` | 导出明文备份 |
| POST | `/api/import` | 导入备份（兼容标准格式/裸数组/单账户） |

## 项目结构

```
bao-auth/
├── main.go                  # 入口，embed 静态文件
├── build.sh                 # 跨平台构建脚本
├── upgrade.sh               # 服务器升级脚本（带回滚）
├── release.sh               # 一键发布：编译+上传+升级
├── internal/
│   ├── crypto/crypto.go     # scrypt 派生、AES-GCM、bcrypt
│   ├── totp/                # TOTP 码生成
│   ├── store/store.go       # SQLite 持久化
│   ├── auth/auth.go         # KEK 生命周期、JWT、限速
│   └── server/server.go     # HTTP 路由与 handler
├── public/                  # 前端（embed 进二进制）
│   ├── index.html
│   ├── style.css
│   ├── app.js
│   └── vendor/jsqr-1.4.0.js
└── data/                    # SQLite 文件（运行时生成，gitignore）
```
