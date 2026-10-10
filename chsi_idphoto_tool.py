#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
学信网 idphoto 采集码 → OSS 直传 工具箱

用法:
  # 1) 解析二维码内容（拿到 16 位采集码）
  python3 chsi_idphoto_tool.py parse "idphoto/xxxxxxxx/xxxxxxxx=="

  # 2) 在抓包/HAR 里定位「鉴权接口」和「上传接口」
  python3 chsi_idphoto_tool.py find capture.har --keyword 0000000000000000

  # 3) 用鉴权接口返回的 policy 直传本地图片到 OSS
  python3 chsi_idphoto_tool.py upload policy.json /path/to/photo.jpg \
          --endpoint https://chsi-idphotosrv.oss-cn-shanghai.aliyuncs.com
"""

import argparse
import base64
import json
import mimetypes
import os
import re
import sys
import urllib.request
import uuid

MIN_SIZE = 1024        # policy: content-length-range 下限
MAX_SIZE = 1048576     # policy: content-length-range 上限


# --------------------------------------------------------------------------
# 1. 解析二维码
# --------------------------------------------------------------------------
def parse_qr(text: str) -> dict:
    """采集码格式: idphoto/{16位采集码}/{加密学籍信息段}
    注意: 加密段内部可能含 '/'，所以不能用 split('/') 硬切到末尾。
    """
    text = text.strip()
    m = re.match(r"^([A-Za-z0-9_-]+)/([^/]{8,64})/(.+)$", text)
    if not m:
        # 老版本格式：整串就是 base64 明文 JSON
        try:
            raw = base64.b64decode(text, validate=False)
            return {"type": "legacy_base64", "raw": text,
                    "decoded": raw.decode("utf-8", errors="replace")}
        except Exception:
            return {"type": "unknown", "raw": text}

    prefix, cjm, payload = m.group(1), m.group(2), m.group(3)
    info = {
        "type": "idphoto_v2",
        "prefix": prefix,
        "cjm": cjm,               # 16 位采集码 —— 上传鉴权的真正凭据
        "cjm_len": len(cjm),
        "payload": payload,
        "payload_len": len(payload),
        "raw": text,
    }
    # '.' 不是标准 base64 字符（部分客户端用它替代 '+' 或 '/'），逐个变体尝试
    variants = [payload, payload.replace(".", "+"), payload.replace(".", "/"),
                payload.replace(".", ""), payload.replace(".", "+").replace("-", "+")]
    for vi, v in enumerate(variants):
        try:
            raw = base64.b64decode(v, validate=False)
        except Exception:
            continue
        info["payload_variant"] = vi
        info["payload_bytes"] = len(raw)
        info["payload_hex_head"] = raw[:16].hex()
        try:
            info["payload_text"] = raw.decode("utf-8")
            info["payload_is_plaintext"] = True
        except Exception:
            info["payload_is_plaintext"] = False
        break
    else:
        info["payload_decode_error"] = "所有 base64 变体均解码失败"
    return info


# --------------------------------------------------------------------------
# 2. 在 HAR 里定位接口
# --------------------------------------------------------------------------
def _har_text(content: dict) -> str:
    txt = content.get("text", "") or ""
    if content.get("encoding") == "base64" and txt:
        try:
            return base64.b64decode(txt).decode("utf-8", errors="replace")
        except Exception:
            return txt
    return txt


def _req_body(req: dict) -> str:
    pd = req.get("postData") or {}
    if pd.get("text"):
        return pd["text"]
    params = pd.get("params") or []
    if params:
        return json.dumps({p.get("name"): p.get("value") for p in params},
                          ensure_ascii=False)
    return ""


def scan_har(har_path: str, keywords: list, show: int = 400) -> None:
    with open(har_path, encoding="utf-8") as f:
        har = json.load(f)
    entries = har.get("log", {}).get("entries", [])
    print(f"[HAR] 共 {len(entries)} 条请求，关键词: {keywords}\n")

    for i, e in enumerate(entries):
        req, resp = e.get("request", {}), e.get("response", {})
        url = req.get("url", "")
        rbody = _req_body(req)
        rtext = _har_text(resp.get("content", {}))
        hay = "\n".join([url, rbody, rtext,
                         json.dumps(req.get("headers", []), ensure_ascii=False)])
        hit = [k for k in keywords if k and k in hay]
        if not hit:
            continue
        print("=" * 78)
        print(f"#{i}  {req.get('method')}  {url}")
        print(f"    命中关键词: {hit}   状态: {resp.get('status')}")
        if rbody:
            print(f"    请求体: {rbody[:show]}")
        if rtext:
            print(f"    响应体: {rtext[:show]}")
        # 标记：响应里带 policy/signature 的，就是「换取上传凭证」的鉴权接口
        if "policy" in rtext and "signature" in rtext:
            print("    >>> 疑似【鉴权/签发上传凭证】接口")
        if "oss-" in url or "aliyuncs.com" in url:
            print("    >>> 疑似【OSS 直传】接口")
        print()


# --------------------------------------------------------------------------
# 3. OSS PostObject 直传
# --------------------------------------------------------------------------
def build_multipart(fields: dict, file_field: str, file_path: str):
    """file 字段必须排在所有字段最后，否则签名校验失败。"""
    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex[:16]
    parts = []
    for k, v in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'
            .encode("utf-8")
        )
    fname = os.path.basename(file_path)
    ctype = mimetypes.guess_type(fname)[0] or "image/jpeg"
    with open(file_path, "rb") as f:
        data = f.read()
    parts.append(
        (f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
         f'filename="{fname}"\r\nContent-Type: {ctype}\r\n\r\n').encode("utf-8")
        + data + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


# osssign 响应(驼峰) → OSS PostObject 表单字段(短横线)
SIGN_MAP = {
    "policy": "policy",
    "xOssCredential": "x-oss-credential",
    "xOssDate": "x-oss-date",
    "signature": "x-oss-signature",
    "securityToken": "x-oss-security-token",
    "objectKey": "key",
    "version": "x-oss-signature-version",
    "successActionStatus": "success_action_status",
}


def sign_to_form(sign: dict) -> tuple:
    """osssign 响应 → (endpoint, 表单字段 dict)"""
    data = sign.get("data", sign)
    fields = {}
    for src, dst in SIGN_MAP.items():
        v = data.get(src)
        if v is not None:
            fields[dst] = str(v)
    endpoint = data.get("host") or ""
    if not endpoint:
        bucket = data.get("bucketName", "")
        endpoint = f"https://{bucket}.oss-cn-shanghai.aliyuncs.com"
    return endpoint, fields


def oss_upload(endpoint: str, policy: dict, image_path: str, file_field="file"):
    size = os.path.getsize(image_path)
    if not (MIN_SIZE <= size <= MAX_SIZE):
        print(f"[!] 文件大小 {size} 字节超出 policy 允许的 {MIN_SIZE}~{MAX_SIZE} 字节")
        return None

    fields = {k: v for k, v in policy.items()
              if k.lower() not in ("file", "endpoint", "host", "bucket")}
    body, ctype = build_multipart(fields, file_field, image_path)

    req = urllib.request.Request(endpoint.rstrip("/") + "/", data=body,
                                 headers={"Content-Type": ctype}, method="POST")
    print(f"[→] POST {endpoint}  ({size} 字节, {len(fields)} 个表单字段, file 置于最后)")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="学信网 idphoto 采集码工具箱")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("parse", help="解析二维码内容")
    p1.add_argument("qr", nargs="?", help="二维码原文，不给则从 stdin 读")

    p2 = sub.add_parser("find", help="在 HAR 中定位鉴权/上传接口")
    p2.add_argument("har")
    p2.add_argument("--keyword", action="append", default=[],
                    help="搜索关键词，可重复传入，如 --keyword 采集码 --keyword policy")

    p3 = sub.add_parser("upload", help="用 policy 直传本地图片")
    p3.add_argument("policy", help="鉴权接口返回的表单字段 JSON")
    p3.add_argument("image")
    p3.add_argument("--endpoint", default="", help="OSS bucket endpoint，不给则从 host 字段取")

    p4 = sub.add_parser("from-sign", help="直接吃 osssign 接口的响应 JSON 并上传")
    p4.add_argument("sign", help="osssign 响应（整包或 data 部分均可）")
    p4.add_argument("image")

    a = ap.parse_args()

    if a.cmd == "parse":
        text = a.qr or sys.stdin.read()
        print(json.dumps(parse_qr(text), ensure_ascii=False, indent=2))

    elif a.cmd == "find":
        scan_har(a.har, a.keyword)

    elif a.cmd == "upload":
        with open(a.policy, encoding="utf-8") as f:
            policy = json.load(f)
        endpoint = a.endpoint or policy.get("host") or ""
        if not endpoint:
            ap.error("policy 里没有 host，请用 --endpoint 指定")
        res = oss_upload(endpoint, policy, a.image)

    elif a.cmd == "from-sign":
        with open(a.sign, encoding="utf-8") as f:
            sign = json.load(f)
        endpoint, fields = sign_to_form(sign)
        if not fields.get("key"):
            ap.error("响应里没有 objectKey，检查是不是 osssign 的响应")
        print(f"[i] endpoint = {endpoint}")
        print(f"[i] key      = {fields['key']}")
        exp = sign.get("data", sign).get("expiration")
        if exp:
            import time
            left = exp / 1000 - time.time()
            print(f"[i] 凭证剩余有效期 ≈ {left:.0f} 秒"
                  f"{'  (已过期，需要重新签发)' if left < 5 else ''}")
        res = oss_upload(endpoint, fields, a.image)
        if res:
            code, body = res
            print(f"\n[←] HTTP {code}")
            print(body[:800])
            print("\n[OK] 201 = 上传成功（ETag 在返回 XML 里）" if code == 201
                  else "\n[FAIL] 非 201，检查签名时效 / 字段顺序 / 文件大小")


if __name__ == "__main__":
    main()
