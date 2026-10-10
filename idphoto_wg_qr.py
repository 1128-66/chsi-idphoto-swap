#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
根据 ~/.mitmproxy/wireguard.conf 生成手机端 WireGuard 配置 + 二维码。

mitmproxy 的 TUI 版才会显示二维码；用 mitmdump 后台跑时看不到，
所以需要自己生成。换网络（本机 IP 变了）或密钥重建后，跑一次即可。

用法:
    python3 idphoto_wg_qr.py                # 自动探测本机 IP
    python3 idphoto_wg_qr.py 192.168.1.20   # 手动指定 IP
    python3 idphoto_wg_qr.py --port 51820

产出（本脚本同目录）:
    wg-client.conf     客户端配置文本（扫码失败时手动录入）
    wg-client-qr.png   二维码
"""

import base64
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

WG_CONF = os.path.expanduser("~/.mitmproxy/wireguard.conf")
OUT_CONF = os.path.join(HERE, "wg-client.conf")
OUT_QR = os.path.join(HERE, "wg-client-qr.png")


def x25519_pub(priv_b64: str) -> str:
    """从 WireGuard 私钥派生公钥（base64）。优先用 cryptography，否则纯 Python 兜底。"""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        k = X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
        return base64.b64encode(k.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    except ImportError:
        return x25519_pub_pure(base64.b64decode(priv_b64))


def x25519_pub_pure(priv: bytes) -> str:
    """纯 Python X25519（严格照 RFC 7748 的 Montgomery ladder），无依赖兜底。"""
    P = 2 ** 255 - 19
    A24 = 121665          # RFC 7748: (486662 - 2) / 4，不是 121666

    def clamp(k: bytes) -> int:
        k = bytearray(k)
        k[0] &= 248      # 清低 3 位
        k[31] &= 127     # 清最高位
        k[31] |= 64      # 置次高位
        return int.from_bytes(bytes(k), "little")

    def cswap(swap, a, b):
        return (b, a) if swap else (a, b)

    k = clamp(priv)
    x1 = 9                 # u-coordinate of base point
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = k_t

        A = (x2 + z2) % P
        AA = A * A % P
        B = (x2 - z2) % P
        BB = B * B % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = D * A % P
        CB = C * B % P
        x3 = (DA + CB) ** 2 % P
        z3 = x1 * (DA - CB) ** 2 % P
        x2 = AA * BB % P
        z2 = E * (AA + A24 * E) % P

    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)

    y = x2 * pow(z2, P - 2, P) % P
    return base64.b64encode(y.to_bytes(32, "little")).decode()


def save_qr(conf: str, path: str) -> bool:
    """生成二维码。scale 按内容长度自适应，避免图案过密反而扫不动。"""
    try:
        import segno
        qr = segno.make(conf, error="L")
        ver = qr.version
        scale = 9 if ver <= 12 else (7 if ver <= 22 else 6)
        qr.save(path, scale=scale, border=3, dark="#111111", light="#ffffff")
        return True
    except ImportError:
        return False
    except Exception as e:
        print(f"  ⚠️ 二维码生成失败：{e}")
        return False


def local_ip() -> str:
    """取本机局域网 IP：优先 en0（Wi-Fi），再 en1（有线/雷雳）。"""
    for iface in ("en0", "en1"):
        try:
            out = subprocess.run(["ipconfig", "getifaddr", iface],
                                 capture_output=True, text=True, timeout=5)
            ip = out.stdout.strip()
            if ip:
                return ip
        except Exception:
            pass
    return ""


def main() -> int:
    argv = sys.argv[1:]
    args = [a for a in argv if not a.startswith("--")]

    ip = args[0] if args else local_ip()
    if not ip:
        print("✗ 取不到本机 IP，请手动指定：python3 idphoto_wg_qr.py <IP>")
        return 1

    port = "51820"
    if "--port" in argv:
        i = argv.index("--port")
        if i + 1 < len(argv):
            port = argv[i + 1]

    if not os.path.exists(WG_CONF):
        print(f"✗ 找不到 {WG_CONF}")
        print("  先运行一次 mitmproxy 的 wireguard 模式（启动换图代理.command）让它生成密钥。")
        return 1

    with open(WG_CONF, encoding="utf-8") as f:
        keys = json.load(f)
    server_priv = keys["server_key"]
    client_priv = keys["client_key"]

    # ★ 关键：客户端 [Peer] PublicKey 必须是【服务端】公钥。
    #   WireGuardServerInstance 里那个 pubkey 字段其实是客户端公钥，别用错。
    server_pub = x25519_pub(server_priv)

    conf = f"""[Interface]
PrivateKey = {client_priv}
Address = 10.0.0.1/32
DNS = 10.0.0.53

[Peer]
PublicKey = {server_pub}
AllowedIPs = 0.0.0.0/0
Endpoint = {ip}:{port}
"""
    with open(OUT_CONF, "w", encoding="utf-8") as f:
        f.write(conf)

    qr_ok = save_qr(conf, OUT_QR)

    print(f"  Endpoint   : {ip}:{port}")
    print(f"  AllowedIPs : 0.0.0.0/0（全部流量走隧道）")
    print()
    print(f"✓ 客户端配置: {OUT_CONF}")
    print(f"{'✓' if qr_ok else '✗'} 二维码: {OUT_QR}" + ("" if qr_ok else "（缺 segno，跳过）"))
    if not qr_ok:
        print("  装一下：pip3 install segno")
    return 0


if __name__ == "__main__":
    sys.exit(main())
