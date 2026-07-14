#!/bin/bash
# release.sh：本地一键编译 + 上传 + 远程升级。
#
# 用法：
#   ./release.sh                              # 用默认/环境变量
#   ./release.sh user@server                  # 指定服务器（SSH 目标）
#   ./release.sh user@server linux/arm64      # 指定服务器 + 目标平台
#   TARGET=linux/arm64 ./release.sh user@server
#
# 参数优先级：命令行 > 环境变量 > 默认值。
# 可用环境变量：SERVER、TARGET、REMOTE_DIR、SSH_OPTS
set -euo pipefail

# --- 参数解析 ---
SERVER="${SERVER:-}"
TARGET="${TARGET:-linux/amd64}"
REMOTE_DIR="${REMOTE_DIR:-/opt/bao-auth}"
SSH_OPTS="${SSH_OPTS:-}"

# 命令行参数覆盖
if [ $# -ge 1 ]; then SERVER="$1"; fi
if [ $# -ge 2 ]; then TARGET="$2"; fi

if [ -z "$SERVER" ]; then
  echo "用法: $0 <user@server> [target]"
  echo "  或: SERVER=user@server $0"
  echo
  echo "  target 默认 linux/amd64，可选 linux/arm64 等"
  echo "  可用环境变量: SERVER TARGET REMOTE_DIR SSH_OPTS"
  exit 1
fi

# --- 颜色 ---
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
RED=$'\033[31m'
RESET=$'\033[0m'

# --- 拆分目标平台 ---
OS="${TARGET%/*}"
ARCH="${TARGET#*/}"
BINARY="dist/bao-auth-${OS}-${ARCH}"

echo "${YELLOW}▶ 编译 $TARGET ...${RESET}"
./build.sh "$TARGET" >/dev/null || { echo "${RED}✘ 编译失败${RESET}"; exit 1; }
[ -f "$BINARY" ] || { echo "${RED}✘ 找不到产物 $BINARY${RESET}"; exit 1; }
echo "  ${GREEN}✓${RESET} $(du -h "$BINARY" | cut -f1) $BINARY"

echo "${YELLOW}▶ 上传到 $SERVER:$REMOTE_DIR/ ...${RESET}"
scp $SSH_OPTS "$BINARY" "$SERVER:$REMOTE_DIR/bao-auth.new"
echo "  ${GREEN}✓${RESET} 上传完成"

echo "${YELLOW}▶ 远程升级 ...${RESET}"
ssh $SSH_OPTS "$SERVER" "cd $REMOTE_DIR && sudo ./upgrade.sh bao-auth.new"

echo "${GREEN}✓ 发布完成${RESET}"
