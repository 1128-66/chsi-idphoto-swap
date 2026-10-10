#!/bin/bash
# ============================================================
#  学信网 idphoto 换图代理 —— 双击运行
#
#  流程：选一张证件照 → 自动压缩到合规体积 → 生成/核对隧道二维码
#        → 启动代理 → 手机走 App 流程 → 上传成功后代理保持运行
#        （手机还要靠它联网走完后续步骤）→ 按任意键收尾
#
#  前提：手机和 Mac 连在同一个局域网（同一个 Wi-Fi），
#        手机上装了 WireGuard 并已导入本目录的 wg-client.conf。
#
#  ⚠️ 这个终端窗口全程不要关，关了代理就停、手机会断网
# ============================================================

cd "$(dirname "$0")" || exit 1

MITM=/opt/homebrew/bin/mitmdump
[ -x "$MITM" ] || MITM=$(command -v mitmdump)
if [ -z "$MITM" ]; then
    echo "✗ 找不到 mitmdump，请先：brew install mitmproxy"
    exit 1
fi

# ---------- 找一个可用的 python ----------
PY=""
for c in \
    "/opt/homebrew/bin/python3" \
    "/usr/bin/python3" \
    "$(command -v python3 2>/dev/null)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then PY="$c"; break; fi
done

LOGF="$HOME/idphoto_replace.log"
WORK=/tmp/idphoto_upload.jpg

size() { stat -f%z "$1" 2>/dev/null || echo 0; }

pick_photo() {
    osascript 2>/dev/null <<AS
try
    set f to choose file with prompt "$1"
    return POSIX path of f
on error
    return ""
end try
AS
}

prepare_image() {
    local src="$1"
    : > "$WORK"
    local ext
    ext=$(echo "${src##*.}" | tr '[:upper:]' '[:lower:]')
    case "$ext" in
        jpg|jpeg) cp "$src" "$WORK" ;;
        png|bmp|tiff|heic|webp)
            sips -s format jpeg "$src" --out "$WORK" >/dev/null 2>&1 || cp "$src" "$WORK"
            ;;
        *) echo "✗ 不支持的格式：$ext（用 jpg / png）"; return 1 ;;
    esac

    if [ "$(size "$WORK")" -gt 1048576 ]; then
        echo "图片 $(size "$WORK") 字节，超过 1MB，正在压缩..."
        for plan in "1600 80" "1200 80" "1000 75" "800 70" "640 70"; do
            [ "$(size "$WORK")" -le 1048576 ] && break
            set -- $plan
            sips -Z "$1" "$WORK" --out "$WORK" >/dev/null 2>&1
            sips -s formatOptions "$2" "$WORK" --out "$WORK" >/dev/null 2>&1
        done
    fi

    local s
    s=$(size "$WORK")
    if [ "$s" -lt 1024 ] || [ "$s" -gt 1048576 ]; then
        echo "✗ 压缩后 $s 字节，仍不在 1KB~1MB 区间。"
        return 1
    fi
    export IDPHOTO_FILE="$WORK"
    return 0
}

# Ctrl-C：杀掉 mitmdump 并退出。
# 注意用 TERM 不能用 INT —— bash 会把后台作业的 SIGINT 设为忽略，发 INT 它收不到。
MPID=""
cleanup() {
    if [ -n "$MPID" ]; then
        echo
        echo "  正在停止代理..."
        kill -TERM "$MPID" 2>/dev/null
        wait "$MPID" 2>/dev/null
        MPID=""
    fi
}
trap 'cleanup; echo "已退出。记得把手机上的 WireGuard 开关关掉。"; exit 0' INT TERM

# ---------- 1. 选照片 ----------
PHOTO="$1"
[ -z "$PHOTO" ] && PHOTO=$(pick_photo "选择要上传的证件照（jpg / png）")
if [ -z "$PHOTO" ]; then
    echo "未选择照片，退出。"
    exit 0
fi
if [ ! -f "$PHOTO" ]; then
    echo "✗ 文件不存在：$PHOTO"
    exit 1
fi

# ---------- 2. 压缩到合规体积 ----------
if ! prepare_image "$PHOTO"; then
    exit 1
fi
W=$(sips -g pixelWidth  "$WORK" 2>/dev/null | awk '/pixelWidth/{print $2}')
H=$(sips -g pixelHeight "$WORK" 2>/dev/null | awk '/pixelHeight/{print $2}')

# ---------- 3. 本机 IP ----------
IP=$(ipconfig getifaddr en0 2>/dev/null)
[ -z "$IP" ] && IP=$(ipconfig getifaddr en1 2>/dev/null)
if [ -z "$IP" ]; then
    echo "⚠️  自动取不到本机 IP（可能没连 Wi-Fi）"
    printf "请手动输入 Mac 的局域网 IP（如 192.168.1.20）："
    read -r IP
fi
if [ -z "$IP" ]; then
    echo "✗ 没有 IP，退出。连上 Wi-Fi 后重试。"
    exit 1
fi

# ---------- 4. 端口自检 ----------
if lsof -nP -iUDP:51820 >/dev/null 2>&1; then
    echo "⚠️  51820 端口被占用，等 3 秒看是否自动释放..."
    sleep 3
    if lsof -nP -iUDP:51820 >/dev/null 2>&1; then
        echo "✗ 端口仍被占用，请先：pkill -f mitmdump"
        exit 1
    fi
fi

# ---------- 5. 二维码核对 ----------
QR_IP=""
[ -f wg-client.conf ] && QR_IP=$(grep -o 'Endpoint = [^ ]*' wg-client.conf | awk '{print $3}' | cut -d: -f1)

echo
echo "================================================================"
echo "  学信网 idphoto 换图代理"
echo "================================================================"
echo "  本机 IP      : $IP"
echo "  上传图片     : $PHOTO"
echo "               → $WORK  ${W}x${H}, $(size "$WORK") 字节"
echo "  日志         : $LOGF"
echo

if [ ! -f wg-client.conf ] || [ "$QR_IP" != "$IP" ]; then
    if [ -n "$PY" ] && [ -f "$HOME/.mitmproxy/wireguard.conf" ]; then
        echo "  ⟳ 二维码缺失或 IP 变了，正在重新生成..."
        "$PY" idphoto_wg_qr.py "$IP" 2>&1 | sed 's/^/     /'
        [ -f wg-client-qr.png ] && open wg-client-qr.png 2>/dev/null
        echo
    elif [ -n "$QR_IP" ]; then
        echo "  ⚠️  二维码里的 IP 是 $QR_IP，现在是 $IP"
        echo "      手机 WireGuard 里编辑隧道，把 Endpoint 改成 $IP:51820 即可。"
        echo
    fi
fi

echo "  ① 手机打开 WireGuard 开关"
echo "     → 出现   ✓ 手机已连入隧道（10.0.0.x）   说明连上了"
echo "  ② 走 App 流程（扫码 → 拍照 → 上传）"
echo "     → 出现   🔒 服务端存的就是本地图   即替换成功"
echo "  ③ 代理不会自动停：在 App 里等出预览、点确认"
echo "     → 确认好后回到本窗口按任意键，脚本才收尾"
echo "  ④ 收尾后再关掉手机上的开关"
echo
echo "     ✖ 开头的都是失败/拦截，会附具体原因"
echo "  ⚠️  本窗口不要关闭！"
echo "================================================================"
echo

# ---------- 6. 启动代理 ----------
: > "$LOGF"          # 先清空，避免上一轮的成功标记被误判
"$MITM" -m "wireguard@${IP}:51820" \
    -s mitm_replace_photo.py \
    --allow-hosts 'chsi-idphotosrv\.oss-cn-shanghai\.aliyuncs\.com' \
    --set flow_detail=0 \
    --set termlog_verbosity=warn &
MPID=$!

# 自检：确认 UDP 51820 真的被这个进程监听了。
# 端口没起来时早点喊出来，免得对着一张扫不通的码白等半天。
sleep 2
if lsof -nP -p "$MPID" -iUDP:51820 >/dev/null 2>&1; then
    echo "  ✓ 隧道端口已监听：UDP $IP:51820"
else
    echo "  ✗ UDP 51820 没起来，先确认上面的报错（端口占用 / 权限）"
fi
echo "  等待手机连入..."
echo

# ---------- 7. 监控 ----------
# ⚠️ 这里踩过坑：以前一检测到成功就立刻 kill mitmdump，而 WireGuard 服务端
#    就跑在 mitmdump 里 —— 它一死 UDP 51820 没了，手机全网断，App 后续的
#    ossrs / checkst / confirm 全走不完。所以成功后只提示，等你按键才收尾。
DONE=0
while kill -0 "$MPID" 2>/dev/null; do
    if [ "$DONE" = "0" ] && grep -q "服务端存的就是本地图" "$LOGF" 2>/dev/null; then
        DONE=1
        echo
        echo "  ✅ 图片已上传成功并通过校验 —— 代理继续运行，不会断网"
        echo
        echo "  手机现在还得靠这条隧道联网，请在 App 里把后续步骤走完："
        echo "     处理中  →  出现你的照片预览  →  点确认"
        printf "  ▶ 确认好后按任意键收尾（Ctrl-C 也可）："
        read -n1 -s -r
        echo
        break
    fi
    sleep 0.5
done

cleanup

# ---------- 8. 小结 ----------
echo
echo "──────────────── 本次结束 ────────────────"
if grep -q "服务端存的就是本地图" "$LOGF" 2>/dev/null; then
    echo "  ✅ 替换成功（详见上方日志 / $LOGF）"
    echo
    echo "  收尾：把手机上的 WireGuard 开关关掉，手机恢复正常上网"
else
    echo "  ⚠️  未检测到成功标记 —— 可能是手动中断，或上传没成功。"
    echo "     日志最后 5 行："
    [ -f "$LOGF" ] && tail -5 "$LOGF" | sed 's/^/       /'
fi
echo "──────────────────────────────────────────"
echo
echo "记得把手机上的 WireGuard 开关关掉，否则手机上不了网。"
