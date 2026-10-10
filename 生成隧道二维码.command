#!/bin/bash
# ============================================================
#  生成手机端 WireGuard 隧道二维码 —— 双击运行
#
#  什么时候需要跑：
#    · 换了 WiFi（Mac 的局域网 IP 变了）
#    · ~/.mitmproxy/wireguard.conf 里的密钥重建过
#    · 第一次给手机配隧道
#
#  产出（本脚本同目录）：
#    wg-client.conf     配置文本（扫码失败时可手动录入）
#    wg-client-qr.png   二维码（生成后自动打开）
# ============================================================

cd "$(dirname "$0")" || exit 1

# ---------- 找一个能用的 python ----------
PY=""
for c in \
    "/opt/homebrew/bin/python3" \
    "/usr/bin/python3" \
    "$(command -v python3 2>/dev/null)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then PY="$c"; break; fi
done

if [ -z "$PY" ]; then
    echo "✗ 找不到 python3"
    exit 1
fi

# ---------- 确保二维码库可用 ----------
if ! "$PY" -c "import segno" >/dev/null 2>&1; then
    echo "正在安装 segno（二维码库）..."
    "$PY" -m pip install -q segno 2>/dev/null \
        || echo "⚠️  segno 安装失败，将只生成配置文件，不出图"
fi

# ---------- 取本机 IP ----------
IP=""
args=()
if [ -f wg-client.conf ]; then
    OLD=$(grep -o 'Endpoint = [^ ]*' wg-client.conf 2>/dev/null | awk '{print $3}' | cut -d: -f1)
    echo "上次生成的 Endpoint：${OLD:-（无）}"
fi
echo

echo "────────────────────────────────────────────"
"$PY" idphoto_wg_qr.py "$@"
RC=$?

if [ $RC -ne 0 ]; then
    echo
    echo "✗ 生成失败。若提示找不到 wireguard.conf，"
    echo "  先双击『启动换图代理.command』运行一次，让 mitmproxy 生成密钥，"
    echo "  关掉它之后再回到这里重新生码。"
    exit $RC
fi

echo
echo "────────────────────────────────────────────"
echo "配置内容（扫码不便时可照着手动录入）："
echo
cat wg-client.conf
echo
echo "────────────────────────────────────────────"

if [ -f wg-client.conf ]; then
    pbcopy < wg-client.conf 2>/dev/null \
        && echo "✓ 配置已复制到剪贴板（扫不动二维码时用『从剪贴板导入』）"
fi

if [ -f wg-client-qr.png ]; then
    echo "已打开二维码窗口，用手机 WireGuard 扫它即可。"
    open wg-client-qr.png 2>/dev/null
else
    echo "⚠️  没有生成图片，请手动用 wg-client.conf 建隧道。"
fi

echo
echo "手机端：WireGuard → 添加隧道 → 扫描二维码 / 从剪贴板导入"
echo "        （换网络后无需删除隧道，编辑里面的 Endpoint 改 IP 即可）"
