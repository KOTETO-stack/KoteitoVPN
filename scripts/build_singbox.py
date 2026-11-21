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

Защита от «одного плохого сервера» (версия 2):
 - Отпечаток uTLS (fp) приводится к тем, что знает sing-box (chrome, firefox, edge, safari, 360,
   qq, ios, android, random, randomized). Всё остальное (например «unsafe») заменяется на chrome:
   в JSON неизвестный отпечаток ломает запуск всей конфигурации, а не одного сервера.
 - В alpn остаются только h2, http/1.1, h3 (мусорные значения выкидываются).
 - Reality без публичного ключа пропускается.
 - Если в системе есть sing-box (в workflow он ставится шагом Install sing-box), каждый сервер
   проверяется командой sing-box check; не прошедшие проверку в подписки не попадают, причины
   выводятся в лог. Если проверка отклоняет больше половины серверов, считается, что сама проверка
   работает неверно, и она не применяется (лучше лишний сервер, чем пустая подписка).

ВАЖНО: поддержку полей fragment/record_fragment в подписке клиентами Karing и Hiddify
нужно проверять замером на LTE (днём, парами, дважды: ночные красные замеры не считаются).
Если клиент поле не знает, он может не импортировать подписку или проигнорировать поле.

Любая ошибка здесь не ломает основную сборку.
"""
import json
import os
import shutil
import subprocess
import tempfile
import time
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
DEFAULT_FP = "chrome"          # отпечаток uTLS для Reality, если в ссылке не указан или неизвестен
VALID_FP = {"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}
VALID_ALPN = {"h2", "http/1.1", "h3"}
UNSUPPORTED_TRANSPORTS = {"xhttp", "splithttp", "kcp", "quic"}

CHECK_TIMEOUT_S = 15           # на одну проверку sing-box check
CHECK_BUDGET_S = 150           # на все проверки вместе; дальше серверы идут без проверки
CHECK_MAX_BAD_SHARE = 0.5      # отклонено больше этой доли: проверке не верим


def log(msg):
    print(msg)


def _q(u):
    return {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)}


def _flag(v):
    return str(v).lower() in ("1", "true")


def _fp(v):
    """Отпечаток uTLS из ссылки -> допустимый для sing-box (иначе chrome)."""
    v = (v or "").strip().lower()
    return v if v in VALID_FP else DEFAULT_FP


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
    alpn = [a.strip() for a in urllib.parse.unquote(q.get("alpn", "")).split(",")]
    alpn = [a for a in alpn if a in VALID_ALPN]
    if alpn:
        tls["alpn"] = alpn
    fp = q.get("fp", "")
    if is_reality:
        tls["utls"] = {"enabled": True, "fingerprint": _fp(fp)}
        tls["reality"] = {"enabled": True, "public_key": q.get("pbk", ""), "short_id": q.get("sid", "")}
    elif fp:
        tls["utls"] = {"enabled": True, "fingerprint": _fp(fp)}
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
        if security == "reality" and not q.get("pbk"):
            return None, "skip"
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
        security = (q.get("security") or "tls").lower()
        if security == "reality" and not q.get("pbk"):
            return None, "skip"
        ob = {"type": "trojan", "tag": name, "server": host, "server_port": port,
              "password": urllib.parse.unquote(u.username or "")}
        if tr:
            ob["transport"] = tr
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


def _check_one(binary, ob, workdir):
    """Один сервер через sing-box check. Возвращает None, если всё хорошо, иначе текст причины."""
    path = os.path.join(workdir, "check.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"outbounds": [ob]}, f, ensure_ascii=False)
    try:
        r = subprocess.run([binary, "check", "-c", path], capture_output=True, text=True,
                           timeout=CHECK_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return None          # зависла сама проверка: сервер не винить
    if r.returncode == 0:
        return None
    text = (r.stderr or r.stdout or "").strip().splitlines()
    return (text[-1] if text else "ошибка без текста")[:160]


def validate_lines(lines):
    """Проверяет серверы командой sing-box check (если sing-box есть).
    Возвращает {номер строки: причина} для серверов, которые sing-box не принимает."""
    binary = shutil.which("sing-box")
    if not binary:
        log("sing-box подписки: sing-box в системе нет, серверы не проверяются командой check")
        return {}
    bad, checked = {}, 0
    started = time.time()
    try:
        with tempfile.TemporaryDirectory() as workdir:
            for i, ln in enumerate(lines):
                if time.time() - started > CHECK_BUDGET_S:
                    log("sing-box подписки: проверка остановлена по времени (%d из %d серверов проверено)"
                        % (checked, len(lines)))
                    break
                try:
                    ob, _st = convert(ln, True, True)
                except Exception:
                    continue
                if ob is None:
                    continue
                checked += 1
                reason = _check_one(binary, ob, workdir)
                if reason:
                    bad[i] = (ob.get("tag", "VPN"), reason)
    except Exception as e:
        log("sing-box подписки: проверка серверов не выполнена (%s)" % e)
        return {}
    if checked and len(bad) > CHECK_MAX_BAD_SHARE * checked:
        first = next(iter(bad.values()))
        log("sing-box подписки: проверка отклонила %d из %d серверов, это слишком много, проверке не "
            "верим и не применяем (пример: %s: %s)" % (len(bad), checked, first[0], first[1]))
        return {}
    log("sing-box подписки: проверено командой check %d серверов, отклонено %d" % (checked, len(bad)))
    for tag, reason in list(bad.values())[:8]:
        log("  не принят sing-box: %s | %s" % (tag, reason))
    return bad


def build():
    if not os.path.exists(IN_FILE):
        log("sing-box подписки: нет %s, пропуск" % IN_FILE)
        return False
    with open(IN_FILE, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if "://" in ln]
    bad = validate_lines(lines)
    ok_any = False
    for name, frag, rec in VARIANTS:
        outbounds, tags = [], {}
        stat = {"frag": 0, "plain": 0, "skip": 0, "bad": 0}
        for i, ln in enumerate(lines):
            if i in bad:
                stat["bad"] += 1
                continue
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
            log("sing-box подписка %s: серверов нет, файл не перезаписан" % name)
            continue
        path = os.path.join(OUT_DIR, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"outbounds": outbounds}, f, ensure_ascii=False, indent=1)
        log("sing-box подписка %s (fragment=%s, record_fragment=%s): %d серверов "
            "(TLS-блок %d, без него %d, пропущено %d: xhttp и без адреса, не принято sing-box %d)"
            % (name, frag, rec, len(outbounds), stat["frag"], stat["plain"], stat["skip"], stat["bad"]))
        ok_any = True
    return ok_any


def main():
    try:
        build()
    except Exception as e:
        log("sing-box подписка не собрана: %s" % e)


if __name__ == "__main__":
    main()
