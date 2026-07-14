#!/bin/bash
# release.sh：本地一键编译 + 上传 + 远程升级。
#
# 用法：
#   ./release.sh -s user@server                        # 最简（默认 linux/amd64）
#   ./release.sh -s user@server -t linux/arm64         # 指定平台
#   ./release.sh -s user@server -d /opt/bao-auth       # 指定远程目录
#   ./release.sh -s user@server -o "-p 2222"           # 附加 SSH 参数
#
# 选项：
#   -s  SSH 目标（user@server），必填
#   -t  目标平台，默认 linux/amd64
#   -d  远程目录，默认 /opt/bao-auth
#   -o  额外 SSH 参数（如 "-i key -p 2222"）
#   -h  显示帮助
set -euo pipefail

usage() {
  cat <<EOF
用法: $0 -s <user@server> [-t target] [-d dir] [-o ssh_opts]

选项:
  -s  SSH 目标，如 deploy@10.0.0.1（必填）
  -t  目标平台，默认 linux/amd64
  -d  远程目录，默认 /opt/bao-auth
  -o  额外 SSH 参数，如 "-i ~/.ssh/key -p 2222"
  -h  显示本帮助

示例:
  $0 -s deploy@prod
  $0 -s deploy@prod -t linux/arm64
  $0 -s deploy@prod -o "-p 2222"
EOF
}

# --- 解析参数 ---
SERVER=""
TARGET="linux/amd64"
REMOTE_DIR="/opt/bao-auth"
SSH_OPTS=""

while getopts ":s:t:d:o:h" opt; do
  case $opt in
    s) SERVER="$OPTARG" ;;
    t) TARGET="$OPTARG" ;;
    d) REMOTE_DIR="$OPTARG" ;;
    o) SSH_OPTS="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "未知选项: -$OPTARG" >&2; usage; exit 1 ;;
    :)  echo "选项 -$OPTARG 需要参数" >&2; usage; exit 1 ;;
  esac
done

if [ -z "$SERVER" ]; then
  echo "错误：缺少必填选项 -s" >&2
  echo
  usage
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
# shellcheck disable=SC2086 # SSH_OPTS 需要按词拆分，故不加引号
ssh $SSH_OPTS "$SERVER" "mkdir -p $REMOTE_DIR"   # 确保远程目录存在（首次部署）
scp $SSH_OPTS "$BINARY" upgrade.sh "$SERVER:$REMOTE_DIR/"
echo "  ${GREEN}✓${RESET} 二进制 + upgrade.sh 上传完成"

echo "${YELLOW}▶ 远程升级 ...${RESET}"
# shellcheck disable=SC2086
ssh $SSH_OPTS "$SERVER" "cd $REMOTE_DIR && chmod +x upgrade.sh && sudo ./upgrade.sh bao-auth.new"

echo "${GREEN}✓ 发布完成${RESET}"
