#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_singbox.py
Делает из готовой подписки output/subscription_readable.txt подписки в формате sing-box JSON
с TLS-фрагментацией (обход DPI на стороне клиента) для Karing и Hiddify. Это ТЕСТОВЫЕ
подписки рядом с обычными: прежние файлы не меняются. Серверы, порядок и названия
берутся из основной подписки как есть. Четыре варианта (VARIANTS), обычный JSON, не base64:
 - output/subscription_frag.json      fragment + record_fragment (оба)
 - output/subscription_frag_tcp.json  только fragment (режет на TCP-сегменты)
 - output/subscription_frag_rec.json  только record_fragment (режет на TLS-записи)
 - output/subscription_frag_off.json  без фрагментации (КОНТРОЛЬ: тот же JSON, но без
   обхода; отделяет эффект фрагментации от эффекта самого формата JSON в клиенте)

Что делает:
 - vless и trojan с TLS или Reality получают в блоке tls поля fragment и/или
   record_fragment (по варианту): клиент режет первый пакет рукопожатия на куски,
   и простой DPI не видит имя (SNI);
 - hysteria2 идёт без фрагментации (это UDP/QUIC, фрагментация TCP-рукопожатия не при чём);
 - транспорт xhttp в sing-box не поддерживается: такие серверы пропускаются (число в логе);
 - vless/trojan без TLS и Reality идут как есть, без фрагментации.

ВАЖНО: поддержку полей fragment/record_fragment в подписке клиентами Karing и Hiddify
нужно проверять замером на LTE (днём, парами, дважды: ночные красные замеры не считаются).
Если клиент поле не знает, он может не импортировать подписку или проигнорировать поле.

Любая ошибка здесь не ломает основную сборку.
"""
import json
import os
import urllib.parse

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "output")
IN_FILE = os.path.join(OUT_DIR, "subscription_readable.txt")

# (имя файла, fragment, record_fragment)
VARIANTS = [
    ("subscription_frag.json", True, True),
    ("subscription_frag_tcp.json", True, False),
    ("subscription_frag_rec.json", False, True),
    ("subscription_frag_off.json", False, False),   # контроль
]
DEFAULT_FP = "chrome"          # отпечаток uTLS для Reality, если в ссылке не указан
UNSUPPORTED_TRANSPORTS = {"xhttp", "splithttp", "kcp", "quic"}


def _q(u):
    return {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)}


def _flag(v):
    return str(v).lower() in ("1", "true")


def _transport(q):
    t = (q.get("type") or "tcp").lower()
    if t in ("tcp", "raw", ""):
        if (q.get("headertype") or "").lower() == "http":
            return None, True
        return None, False
    if t in UNSUPPORTED_TRANSPORTS:
        return None, True
    path = urllib.parse.unquote(q.get("path", "")) or "/"
    host = q.get("host", "")
    if t == "ws":
        tr = {"type": "ws", "path": path}
        if host:
            tr["headers"] = {"Host": host}
        return tr, False
    if t == "grpc":
        return {"type": "grpc", "service_name": urllib.parse.unquote(q.get("servicename", ""))}, False
    if t == "httpupgrade":
        tr = {"type": "httpupgrade", "path": path}
        if host:
            tr["host"] = host
        return tr, False
    return None, True


def _tls(q, host, frag, rec):
    security = (q.get("security") or "").lower()
    is_reality = security == "reality"
    sni = q.get("sni") or q.get("peer") or q.get("servername") or ""
    tls = {"enabled": True, "server_name": sni or host}
    if _flag(q.get("insecure", "")) or _flag(q.get("allowinsecure", "")):
        tls["insecure"] = True
    alpn = [a for a in urllib.parse.unquote(q.get("alpn", "")).split(",") if a]
    if alpn:
        tls["alpn"] = alpn
    fp = q.get("fp", "")
    if is_reality:
        tls["utls"] = {"enabled": True, "fingerprint": fp or DEFAULT_FP}
        tls["reality"] = {"enabled": True, "public_key": q.get("pbk", ""), "short_id": q.get("sid", "")}
    elif fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if frag:
        tls["fragment"] = True
    if rec:
        tls["record_fragment"] = True
    return tls


def convert(uri, frag=True, rec=True):
    """Ссылка -> (outbound, статус). Статус: 'frag' (TLS-блок есть), 'plain', 'skip'."""
    u = urllib.parse.urlparse(uri.strip())
    scheme = (u.scheme or "").lower()
    name = urllib.parse.unquote(u.fragment) or "VPN"
    host, port = u.hostname, u.port
    if not host or port is None:
        return None, "skip"
    q = _q(u)

    if scheme == "vless":
        tr, bad = _transport(q)
        if bad:
            return None, "skip"
        security = (q.get("security") or "").lower()
        ob = {"type": "vless", "tag": name, "server": host, "server_port": port,
              "uuid": urllib.parse.unquote(u.username or ""), "packet_encoding": "xudp"}
        if q.get("flow"):
            ob["flow"] = q["flow"]
        if tr:
            ob["transport"] = tr
        if security in ("tls", "reality"):
            ob["tls"] = _tls(q, host, frag, rec)
            return ob, "frag"
        return ob, "plain"

    if scheme == "trojan":
        tr, bad = _transport(q)
        if bad:
            return None, "skip"
        ob = {"type": "trojan", "tag": name, "server": host, "server_port": port,
              "password": urllib.parse.unquote(u.username or "")}
        if tr:
            ob["transport"] = tr
        security = (q.get("security") or "tls").lower()
        if security == "none":
            return ob, "plain"
        ob["tls"] = _tls(q, host, frag, rec)
        return ob, "frag"

    if scheme in ("hysteria2", "hy2"):
        pwd = urllib.parse.unquote(u.username or "")
        if u.password:
            pwd = "%s:%s" % (pwd, urllib.parse.unquote(u.password))
        ob = {"type": "hysteria2", "tag": name, "server": host, "server_port": port,
              "password": pwd, "tls": _tls(q, host, False, False)}
        if q.get("obfs"):
            ob["obfs"] = {"type": q["obfs"], "password": q.get("obfs-password", "")}
        return ob, "plain"

    return None, "skip"


def build():
    if not os.path.exists(IN_FILE):
        print("sing-box подписки: нет %s, пропуск" % IN_FILE)
        return False
    with open(IN_FILE, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if "://" in ln]
    ok_any = False
    for name, frag, rec in VARIANTS:
        outbounds, tags = [], {}
        stat = {"frag": 0, "plain": 0, "skip": 0}
        for ln in lines:
            try:
                ob, st = convert(ln, frag, rec)
            except Exception:
                ob, st = None, "skip"
            stat[st] += 1
            if ob is None:
                continue
            base = ob["tag"]
            n = tags.get(base, 0) + 1
            tags[base] = n
            if n > 1:
                ob["tag"] = "%s %d" % (base, n)
            outbounds.append(ob)
        if not outbounds:
            print("sing-box подписка %s: серверов нет, файл не перезаписан" % name)
            continue
        path = os.path.join(OUT_DIR, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"outbounds": outbounds}, f, ensure_ascii=False, indent=1)
        print("sing-box подписка %s (fragment=%s, record_fragment=%s): %d серверов "
              "(TLS-блок %d, без него %d, пропущено %d: xhttp и без адреса)"
              % (name, frag, rec, len(outbounds), stat["frag"], stat["plain"], stat["skip"]))
        ok_any = True
    return ok_any


def main():
    try:
        build()
    except Exception as e:
        print("sing-box подписка не собрана: %s" % e)


if __name__ == "__main__":
    main()
