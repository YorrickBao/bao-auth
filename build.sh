#!/usr/bin/env bash
# 跨平台构建脚本：交叉编译到 dist/ 目录。
#
# 用法：
#   ./build.sh              # 构建全部目标平台
#   ./build.sh linux/amd64  # 只构建指定目标（可多个，空格分隔）
#
# 产物：dist/bao-auth-{os}-{arch}[.exe]
set -euo pipefail

# 默认目标：主流 OS × 架构组合。纯 Go 零 CGO，交叉编译无需额外工具链。
DEFAULT_TARGETS=(
  "darwin/arm64"   # macOS Apple Silicon
  "darwin/amd64"   # macOS Intel
  "linux/amd64"    # Linux x86-64（最常见服务器）
  "linux/arm64"    # Linux ARM（Graviton / 树莓派 4）
  "windows/amd64"  # Windows x86-64
)

TARGETS=("${@:-${DEFAULT_TARGETS[@]}}")
DIST="dist"
LDFLAGS="-s -w"  # 去掉符号表和调试信息，减小约 30% 体积

# 颜色输出
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
RED=$'\033[31m'
RESET=$'\033[0m'

echo "${YELLOW}构建目标：${TARGETS[*]}${RESET}"

# 清理并重建 dist 目录
rm -rf "$DIST"
mkdir -p "$DIST"

# 逐个目标编译
fail=0
for target in "${TARGETS[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"

  # 产物名：Windows 带 .exe 后缀
  out="$DIST/bao-auth-${os}-${arch}"
  [[ "$os" == "windows" ]] && out="${out}.exe"

  printf "  %-18s → %s ... " "$target" "$out"
  if GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o "$out" .; then
    size=$(du -h "$out" | cut -f1)
    echo "${GREEN}OK${RESET} (${size})"
  else
    echo "${RED}FAIL${RESET}"
    fail=$((fail + 1))
  fi
done

# 生成校验文件，便于部署时验证完整性
if command -v shasum &>/dev/null; then
  (cd "$DIST" && shasum -a 256 bao-auth-* > sha256sums.txt)
  echo "${YELLOW}已生成 dist/sha256sums.txt${RESET}"
fi

echo ""
ls -lh "$DIST"/

if [[ $fail -gt 0 ]]; then
  echo "${RED}完成，但 ${fail} 个目标失败。${RESET}"
  exit 1
fi
echo "${GREEN}全部构建成功。${RESET}"
