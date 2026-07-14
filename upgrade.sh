#!/bin/bash
# bao-auth 升级脚本：替换二进制并重启服务，失败自动回滚。
#
# 用法（在服务器上）：
#   sudo ./upgrade.sh <新二进制路径>
#
# 示例：
#   scp dist/bao-auth-linux-amd64 user@server:/opt/bao-auth/bao-auth.new
#   ssh user@server 'cd /opt/bao-auth && sudo ./upgrade.sh bao-auth.new'
set -euo pipefail

APP_DIR="/opt/bao-auth"
SERVICE="bao-auth"
NEW="${1:-bao-auth.new}"

cd "$APP_DIR"

if [ ! -f "$NEW" ]; then
  echo "❌ 找不到新二进制：$NEW"
  echo "   用法：sudo $0 <新二进制路径>"
  exit 1
fi

echo "📥 正在替换二进制..."
mv bao-auth bao-auth.old
mv "$NEW" bao-auth
chown baoauth:baoauth bao-auth
chmod +x bao-auth

echo "🔄 正在重启服务..."
systemctl restart "$SERVICE"

sleep 1
if systemctl is-active --quiet "$SERVICE"; then
  echo "✅ 升级成功，服务运行中"
  rm -f bao-auth.old
  systemctl status "$SERVICE" --no-pager | head -5
else
  echo "❌ 服务启动失败，回滚到旧版本..."
  mv bao-auth bao-auth.failed
  mv bao-auth.old bao-auth
  chown baoauth:baoauth bao-auth
  chmod +x bao-auth
  systemctl restart "$SERVICE"
  echo "已回滚。失败的新版本保留为 bao-auth.failed 供排查。"
  exit 1
fi
