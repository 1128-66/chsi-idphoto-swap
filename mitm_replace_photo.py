#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mitmproxy 插件：拦截学信网 idphoto 的 OSS 直传请求，把照片替换成本地图片。

为什么这么做：
  鉴权链路（v1/check → osssign，JWE 加密的 Authorization + 加密的 k/d 参数）
  全部在 App 内部完成，无法用 curl 手工重放。唯一干净的切入点是最后一步
  —— OSS PostObject：签名已经签发好了，只要在请求离开手机前把 file 部分
  换成本地图片，后续 ossrs / checkst / confirm 就都会作用于这张图。

用法（WireGuard 模式，可绕过 App 忽略系统代理的问题）:

    IDPHOTO_FILE=/Users/me/photo.jpg \\
    mitmdump -m wireguard@192.168.1.20:51820 -s mitm_replace_photo.py \\
        --allow-hosts 'chsi-idphotosrv\\.oss-cn-shanghai\\.aliyuncs\\.com'

  手机装 WireGuard，扫 mitmproxy 给的二维码连入，然后照常在 App 里走流程。
  IDPHOTO_FILE 也可以指向一个目录（如 ~/Downloads），此时自动取目录里
  最近修改的那张 jpg/jpeg/png —— 免得每次都要改命令重启。

用法（普通 HTTP 代理，部分 App 会绕过系统代理导致抓不到）:

    IDPHOTO_FILE=/Users/me/photo.jpg mitmdump -s mitm_replace_photo.py \\
        --listen-host 0.0.0.0 -p 8080 \\
        --allow-hosts 'chsi-idphotosrv\\.oss-cn-shanghai\\.aliyuncs\\.com'

日志：终端 + ~/idphoto_replace.log 双写，便于外部监控。
"""

import glob
import hashlib
import os
import re
import time

from mitmproxy import http

TARGET_HOST = "chsi-idphotosrv.oss"
MIN_SIZE, MAX_SIZE = 1024, 1048576   # policy 里的 content-length-range

# 表单固定开销：multipart 里除图片外所有字段的总字节数。
# 由 14 次真实上传反推得到——替换后 body = 本地图字节 + 3763，一次不差。
# 用于自检：偏离说明 replacements 或字段名结构有变，值得警惕。
FORM_OVERHEAD = 3763
LOG_FILE = os.path.expanduser("~/idphoto_replace.log")
IMG_EXT = ("*.jpg", "*.jpeg", "*.png", "*.JPG", "*.JPEG", "*.PNG")


def ctx_log(flow, msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _abort(flow, reason: str) -> None:
    """替换失败时直接掐断这次上传，而不是原样放行。

    这是 fail-safe 设计：一旦走到这里，意味着 multipart 里装的还是 App
    现场拍的照片。若不掐断，这张真照片就会被 OSS 收下并且撤不回来。
    宁可让 App 报一次网络错误（流程可以重走），也不能让原图漏出去。
    照片已经成功换上去的情况不会走到这里。
    """
    ctx_log(flow, f"✖ 已拦截本次上传：{reason}")
    ctx_log(flow, "   请求已掐断，App 现场拍的照片不会离开手机；修好后重走一次流程即可")
    try:
        flow.kill()
    except Exception:
        pass


def _pick_photo(path: str) -> str | None:
    """IDPHOTO_FILE 可以是文件，也可以是目录（取最新一张图片）。"""
    path = os.path.expanduser(path)
    if os.path.isdir(path):
        cands = []
        for ext in IMG_EXT:
            cands.extend(glob.glob(os.path.join(path, ext)))
        if not cands:
            return None
        return max(cands, key=os.path.getmtime)
    return path if os.path.isfile(path) else None


def _swap_file_part(body: bytes, boundary: bytes, data: bytes) -> tuple[bytes, bool]:
    """把 multipart 里文件那一节的正文替换掉，其余字段原样保留。

    优先匹配 name="file"；若没有，退而求其次取第一个带 filename= 的分段，
    （不同客户端字段名可能不同，兜底更稳）。
    """
    sep = b"--" + boundary
    parts = body.split(sep)

    def replace_at(i):
        head_end = parts[i].find(b"\r\n\r\n")
        if head_end < 0:
            return False
        head = parts[i][:head_end]
        parts[i] = head + b"\r\n\r\n" + data + b"\r\n"
        return True

    for i, part in enumerate(parts):
        head_end = part.find(b"\r\n\r\n")
        if head_end < 0:
            continue
        if b'name="file"' in part[:head_end] or b"name='file'" in part[:head_end]:
            if replace_at(i):
                return sep.join(parts), True

    for i, part in enumerate(parts):
        head_end = part.find(b"\r\n\r\n")
        if head_end < 0:
            continue
        if b"filename=" in part[:head_end]:
            if replace_at(i):
                return sep.join(parts), True
    return body, False


_seen_clients: set[str] = set()


def client_connected(client) -> None:
    """手机连入隧道（对端是 10.0.0.x）时报一次。

    mitmproxy 自己的 connect/disconnect 日志被 termlog_verbosity=warn 屏蔽了，
    这条"手机到底连上没有"的信号由本插件补上，去重避免每条 TCP 连接都刷屏。
    """
    try:
        peers = [getattr(client, "peername", None), getattr(client, "address", None)]
        for peer in peers:
            if not peer:
                continue
            host = peer[0] if isinstance(peer, (list, tuple)) else str(peer)
            if host.startswith("10.0.0.") and host not in _seen_clients:
                _seen_clients.add(host)
                ctx_log(None, f"✓ 手机已连入隧道（{host}）")
                return
    except Exception:
        pass


def request(flow: http.HTTPFlow) -> None:
    req = flow.request
    host = req.pretty_host

    # 学信网相关请求一律记一笔：用来确认流量是否真的经过代理
    if "chsi" in host:
        ct = (req.headers.get("content-type") or "").split(";")[0]
        ctx_log(flow, f"⇢ {req.scheme.upper()} {req.method} {host}{req.path[:50]} "
                      f"len={len(req.content) if req.content else 0} ct={ct}")

    if TARGET_HOST not in host or req.method != "POST":
        return

    ctype = req.headers.get("content-type", "")
    m = re.search(r"boundary=([\w\-]+)", ctype)
    if not m:
        _abort(flow, "不是 multipart 请求")
        return

    path = _pick_photo(os.environ.get("IDPHOTO_FILE", "~/photo.jpg"))
    if not path:
        _abort(flow, f"找不到本地图片 {os.environ.get('IDPHOTO_FILE')}")
        return
    with open(path, "rb") as f:
        data = f.read()

    if not (MIN_SIZE <= len(data) <= MAX_SIZE):
        _abort(flow, f"本地图片 {len(data)} 字节，超出 {MIN_SIZE}~{MAX_SIZE}")
        return

    old_len = len(req.content or b"")
    new_body, ok = _swap_file_part(req.content, m.group(1).encode(), data)
    if not ok:
        _abort(flow, "multipart 里找不到文件字段")
        return

    req.content = new_body
    req.headers["content-length"] = str(len(new_body))
    new_len = len(new_body)
    ctx_log(flow, f"✔ 已替换 {os.path.basename(path)}（{len(data)} 字节）；"
                  f"body {old_len} → {new_len}")

    # 记下本地图的 MD5，等 OSS 返回 ETag 时比对
    # （OSS 非分片上传的 ETag 就是对象内容的 MD5，是"服务端到底存了什么"的凭证）
    flow.metadata["idphoto_md5"] = hashlib.md5(data).hexdigest()
    flow.metadata["idphoto_name"] = os.path.basename(path)
    flow.metadata["idphoto_size"] = len(data)
    ctx_log(flow, f"   本地图 MD5 {flow.metadata['idphoto_md5']}")

    overhead = new_len - len(data)
    if overhead != FORM_OVERHEAD:
        ctx_log(flow, f"⚠ 自检未通过：表单开销 {overhead} 字节，历史恒为 {FORM_OVERHEAD}。"
                      f"图片大概率还是上传了，但建议核对上方字段名结构有无变化")


def response(flow: http.HTTPFlow) -> None:
    """顺手记录：osssign 的响应另存一份，方便离线复用；OSS 结果打印出来。"""
    url = flow.request.pretty_url
    if "capture/osssign" in url:
        try:
            with open(os.path.expanduser("~/idphoto_osssign.json"), "wb") as f:
                f.write(flow.response.content)
            ctx_log(flow, "osssign 响应已存到 ~/idphoto_osssign.json")
        except Exception as e:
            ctx_log(flow, f"保存失败: {e}")
    elif TARGET_HOST in flow.request.pretty_host:
        code = flow.response.status_code
        # 注意：ETag 要从未截断的全文里取，打印时才截断
        full = ""
        try:
            full = flow.response.text or ""
        except Exception:
            pass
        body = full[:300].replace("\n", " ")
        if code == 201:
            ctx_log(flow, "🎉 上传成功 —— OSS 返回 201")
            m = re.search(r"<Location>(.*?)</Location>", full)
            if m:
                ctx_log(flow, f"   图片地址 {m.group(1)}")

            # ★ 关键校验：ETag == 本地图 MD5 ⇒ 服务端存的确实是我们这张图
            etag_m = re.search(r"<ETag>(.*?)</ETag>", full, re.I)
            local_md5 = flow.metadata.get("idphoto_md5")
            if etag_m and local_md5:
                etag = etag_m.group(1).strip().strip('"')
                if etag.lower() == local_md5.lower():
                    ctx_log(flow, f"🔒 服务端存的就是本地图 —— ETag 与本地 MD5 一致（{etag}）")
                    ctx_log(flow, "   拍摄的原图未离开手机；可以放心在 App 里确认")
                else:
                    ctx_log(flow, f"⚠ ETag 与本地图不符！服务端 ETag={etag}，"
                                  f"本地 MD5={local_md5} —— 请务必人工复核")
            else:
                ctx_log(flow, "   （响应里没有 ETag，无法做内容比对）")

            ctx_log(flow, "   代理保持运行，手机不会断网；在 App 里等预览 → 点确认")
        else:
            ctx_log(flow, f"✖ 上传失败 —— OSS 返回 {code}")
            ctx_log(flow, f"   {body}")


def error(flow: http.HTTPFlow) -> None:
    ctx_log(flow, f"✖ 连接错误 {flow.request.pretty_host}: {getattr(flow, 'error', '')}")
