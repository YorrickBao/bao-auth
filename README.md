# bao-auth

一个自托管、单二进制的 Web 版 TOTP 验证器（Google Authenticator / Authy 的自部署替代）。

后端用 Go 编写，前端（HTML/CSS/JS）通过 `embed` 打包进同一个二进制文件。
数据加密存储在本地 SQLite，**原始密钥绝不离开服务器**——浏览器只拿到后端实时算出的验证码。

## 特性

- 🔐 **单二进制部署**：前端、后端、数据库驱动全编译进一个 15MB 的可执行文件，零外部依赖
- 🛡️ **加密存储**：主密码经 scrypt 派生 KEK，secret 用 AES-256-GCM 加密；KEK 只存内存，重启即锁
- 🔑 **原始密钥不外泄**：列表/详情接口只返回实时 TOTP 码，绝不回传 secret（仅主动导出时例外）
- ⏱️ **实时倒计时**：本地每秒刷新圆环，到周期边界自动拉取新码
- 📷 **多种添加方式**：手动输入、粘贴 `otpauth://` 链接、上传二维码图片解析
- 🔎 **搜索 / 编辑 / 删除 / 导入导出备份**
- 🚦 **登录限速**：连续失败自动冷却，缓解暴力破解
- 🌗 **深色/浅色自适应**

## 快速开始

### 编译

```bash
go build -o bao-auth .
```

### 运行

```bash
./bao-auth
# 默认监听 http://127.0.0.1:3000，数据存于 ./data/bao-auth.db
```

打开浏览器访问 `http://127.0.0.1:3000`，首次访问设置主密码即可。

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--addr` | `127.0.0.1:3000` | 监听地址 |
| `--data` | `./data` | 数据目录（SQLite 文件存放处） |

示例：`./bao-auth --addr 0.0.0.0:3000 --data /var/lib/bao-auth`

## 部署

### 交叉编译

纯 Go（SQLite 用 `modernc.org/sqlite`，无 CGO），交叉编译零障碍：

```bash
# macOS Apple Silicon → Linux 服务器
GOOS=linux GOARCH=amd64 go build -o bao-auth .
scp bao-auth user@server:~/
```

在服务器上：

```bash
./bao-auth --addr 127.0.0.1:3000
# 建议用 nginx/caddy 反代并配置 HTTPS
```

### systemd 服务示例

```ini
# /etc/systemd/system/bao-auth.service
[Unit]
Description=bao-auth
After=network.target

[Service]
ExecStart=/opt/bao-auth/bao-auth --addr 127.0.0.1:3000 --data /opt/bao-auth/data
WorkingDirectory=/opt/bao-auth
Restart=on-failure
User=baoauth

[Install]
WantedBy=multi-user.target
```

## 安全模型

| 资产 | 存储位置 | 保护方式 |
|------|----------|----------|
| 主密码（bcrypt 哈希） | SQLite | bcrypt（仅用于校验登录） |
| KEK 派生盐 | SQLite | — |
| secret 密文 | SQLite | AES-256-GCM，密钥=主密码派生的 KEK |
| KEK（密钥加密密钥） | **仅内存** | 登录时从主密码实时派生，不落盘；服务器重启即失效 |
| 会话 | 浏览器 sessionStorage | JWT（HS256，签名密钥每次启动随机） |

**重要**：
- 主密码无法找回。遗忘则所有已存 secret 永久不可恢复（密文无法解密）。
- 建议定期使用"导出"功能生成明文 JSON 备份，离线妥善保管。
- 生产环境务必通过 HTTPS 反代访问，避免主密码与验证码在传输中被窃听。

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
| POST | `/api/import` | 导入备份文件（兼容标准格式/裸数组/单账户） |

## 项目结构

```
bao-auth/
├── main.go                  # 入口，embed 静态文件
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
