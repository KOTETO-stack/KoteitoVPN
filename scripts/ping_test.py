#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ping_test.py

Версия 5.3 — реальная проверка: трафик реально пропускается через сервер.
5.3: накопительная история (файл server_history.json, в Actions хранится в кэше):
     серверы, которые уже проходили тест, проверяются в первую очередь в каждом запуске,
     остаются в пуле, пока не провалят HISTORY_MAX_FAILS проверок подряд, и им прощается
     одиночный сбой. Пул растёт и стабилизируется, а не собирается с нуля каждый час.
5.1: шире и разнообразнее выборка для этапа 2 (см. main()).
5.2: type=raw (новое имя tcp в Xray) теперь тестируется; в лог выводится разбивка
     причин, по которым конфиг «не поддерживается».

Этап 1 (быстрый отсев):
 - vless/trojan: TCP-connect + TLS-хендшейк на SNI из конфига;
 - hysteria2: UDP-проб порта.
 Всё, что дороже MAX_PING_MS, отбрасывается.

Этап 2 (главный):
 - каждый оставшийся конфиг превращается в outbound для sing-box (то же ядро,
   что у Karing/Hiddify), sing-box запускается пачками по BATCH_SIZE штук;
 - через локальный SOCKS-порт каждого конфига делается настоящий HTTPS-запрос
   (generate_204) — если ответ пришёл, сервер реально проксирует трафик;
 - затем небольшая загрузка (SPEED_BYTES), очень медленные серверы отбрасываются;
 - в результат добавляются поля real_ms и speed_kbps.

Какие конфиги идут на этап 2 (раньше брались только самые низкие по пингу,
а с GitHub-раннера самый низкий пинг у IP Cloudflare/CDN, которые проходят
TLS с любым SNI, но реальный прокси не дают; Reality-серверы стоят на обычных
VPS, имеют больший пинг и в выборку почти не попадали):
 - Hysteria2: до HY2_CAP штук;
 - Reality: случайная выборка до REALITY_CAP;
 - остальные vless/trojan: FAST_CAP с самым низким пингом + RANDOM_CAP случайных
   из остальных.
Порядок запуска: сначала Hysteria2, потом Reality, потом остальные. Если
бюджет времени кончится, не проверенным останется хвост.

Страховки:
 - нет бинарника sing-box или переменная окружения REAL_TEST=0 -> работает как v4;
 - если реальный тест не пропустил ни одного сервера из 20+ (значит, сломан сам
   тест, а не все серверы) -> берутся результаты этапа 1, подписка не опустеет.

Формат результата не изменился: pinged_configs.json — список dict, поле "ping_ms"
осталось (это пинг этапа 1), сортировка теперь по real_ms.
"""
import concurrent.futures as cf
from collections import Counter
import json
import os
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.parse

BASE_DIR = os.path.dirname(__file__)
IN_FILE = os.path.join(BASE_DIR, "..", "clean_configs.json")
OUT_FILE = os.path.join(BASE_DIR, "..", "pinged_configs.json")

# ---------- этап 1: быстрый отсев ----------
MAX_PING_MS = 500
CONNECT_TIMEOUT = 2.5
UDP_PROBE_TIMEOUT = 1.5
WORKERS = 40

# ---------- этап 2: реальный тест через sing-box ----------
REAL_TEST_ENABLED = os.environ.get("REAL_TEST", "1") != "0"
SINGBOX_BIN = os.environ.get("SINGBOX_BIN") or shutil.which("sing-box") or "/usr/local/bin/sing-box"
HY2_CAP = 800               # максимум Hysteria2 на реальный тест
REALITY_CAP = 2500          # максимум Reality (случайная выборка)
FAST_CAP = 1000             # остальные vless/trojan: столько с самым низким пингом
RANDOM_CAP = 1200           # и столько случайных из остальных
BATCH_SIZE = 120            # конфигов в одном запуске sing-box
BATCH_WORKERS = 60          # параллельных проверок внутри пачки
BASE_PORT = 21000           # локальные SOCKS-порты: BASE_PORT + номер
REAL_TIMEOUT = 6.0          # таймаут одного запроса, сек
SPEED_TIMEOUT = 8.0
MAX_REAL_MS = 4000          # запрос через прокси дольше — сервер считается плохим
SPEED_BYTES = 300000
MIN_SPEED_KBPS = 80         # КБ/с; ниже — отбрасываем (только если скорость реально измерена)
TIME_BUDGET_SEC = 1800      # общий бюджет времени на этап 2 (workflow: timeout 90 мин)
STARTUP_WAIT = 10.0         # сколько ждём старта sing-box

# ---------- история проверенных серверов ----------
HISTORY_FILE = os.environ.get("HISTORY_FILE") or os.path.join(BASE_DIR, "..", "server_history.json")
HISTORY_INJECT = 800        # сколько серверов из истории проверять первыми в каждом запуске
HISTORY_MAX_FAILS = 5       # столько провалов подряд, и сервер удаляется из истории
HISTORY_MAX_AGE_DAYS = 7    # давно не проходившие сервера удаляются
HISTORY_MAX_ENTRIES = 3000  # максимум записей в истории
HISTORY_GRACE_MIN_OK = 3    # сколько проходов нужно, чтобы один сбой подряд простили

LATENCY_TARGETS = [
    ("cp.cloudflare.com", "/generate_204"),
    ("www.gstatic.com", "/generate_204"),
]
SPEED_TARGET = ("speed.cloudflare.com", "/__down?bytes=%d" % SPEED_BYTES)

VALID_FP = {"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}

# причины, по которым конфиг нельзя протестировать через sing-box (для лога)
UNSUPPORTED = Counter()
TESTED_KEYS = set()   # host:port конфигов, которые реально прошли через sing-box в этом запуске


def skip(reason):
    UNSUPPORTED[reason] += 1
    return None


# =====================================================================
#                          ЭТАП 1 (как в v4)
# =====================================================================
def extract_sni(raw, fallback_host):
    """Достаёт sni (или host) параметр из самого конфига."""
    try:
        rest = raw.split("://", 1)[1]
        if "#" in rest:
            rest = rest.split("#", 1)[0]
        hostport_query = rest.split("@", 1)[1] if "@" in rest else rest
        query = hostport_query.split("?", 1)[1] if "?" in hostport_query else ""
        params = dict(urllib.parse.parse_qsl(query))
        return params.get("sni") or params.get("host") or fallback_host
    except Exception:
        return fallback_host


def tcp_or_tls_ping(entry):
    """TCP-connect для всех; для vless/trojan с TLS/Reality — ещё и TLS-хендшейк."""
    host, port = entry["host"], entry["port"]
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        needs_tls = entry.get("proto") in ("vless", "trojan") and entry.get("security_tag") in ("tls", "reality")
        if needs_tls:
            sock.settimeout(CONNECT_TIMEOUT)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sni = extract_sni(entry["raw"], host)
            tls_sock = ctx.wrap_socket(sock, server_hostname=sni, do_handshake_on_connect=True)
            tls_sock.close()
        else:
            sock.close()
        return int((time.perf_counter() - start) * 1000)
    except Exception:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return None


def udp_probe(host, port):
    """Проб UDP-порта Hysteria2-сервера."""
    start = time.perf_counter()
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(UDP_PROBE_TIMEOUT)
        s.connect((host, port))
        s.send(os.urandom(32))
        try:
            s.recvfrom(1024)
            return int((time.perf_counter() - start) * 1000)
        except socket.timeout:
            approx = int(UDP_PROBE_TIMEOUT * 1000) - 200
            return max(50, min(approx, MAX_PING_MS - 1))
        except ConnectionRefusedError:
            return None
    except Exception:
        return None
    finally:
        if s:
            s.close()


def quick_check(entry):
    if entry.get("proto") == "hysteria2":
        ms = udp_probe(entry["host"], entry["port"])
    else:
        ms = tcp_or_tls_ping(entry)
    if ms is None or ms > MAX_PING_MS:
        return None
    entry["ping_ms"] = ms
    return entry


# =====================================================================
#            ЭТАП 2: URI -> outbound для sing-box
# =====================================================================
def parse_uri(raw):
    """Возвращает (scheme, userinfo, params). Ключи params — в нижнем регистре."""
    scheme, rest = raw.split("://", 1)
    rest = rest.split("#", 1)[0]
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    rest = rest.rstrip("/")
    userinfo = urllib.parse.unquote(rest.rsplit("@", 1)[0]) if "@" in rest else ""
    params = {k.lower(): v for k, v in urllib.parse.parse_qsl(query)}
    return scheme.lower(), userinfo, params


def base_tls(params, host):
    sni = params.get("sni") or params.get("peer") or params.get("host") or host
    tls = {"enabled": True, "server_name": sni}
    if params.get("allowinsecure") in ("1", "true") or params.get("insecure") in ("1", "true"):
        tls["insecure"] = True
    alpn = [a for a in params.get("alpn", "").split(",") if a]
    if alpn:
        tls["alpn"] = alpn
    return tls


def make_tls(params, host):
    """TLS/Reality для vless и trojan (uTLS + reality). None — конфиг не собрать."""
    tls = base_tls(params, host)
    security = params.get("security", "")
    fp = params.get("fp", "").lower()
    if security == "reality" and fp not in VALID_FP:
        fp = "chrome"
    if fp in VALID_FP:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if security == "reality":
        pbk = params.get("pbk")
        if not pbk:
            return None
        tls["reality"] = {"enabled": True, "public_key": pbk, "short_id": params.get("sid", "")}
    return tls


def make_transport(params):
    """(ok, transport). ok=False — транспорт sing-box не поддерживает (xhttp, kcp и т.п.)."""
    t = (params.get("type", "tcp") or "tcp").lower()
    if t == "raw":  # новое имя tcp в Xray
        t = "tcp"
    host = params.get("host", "")
    path = params.get("path", "") or "/"
    if t == "tcp":
        ht = params.get("headertype", "none")
        if ht not in ("", "none"):
            return False, "tcp headerType=" + ht
        return True, None
    if t == "ws":
        tr = {"type": "ws", "path": path}
        if host:
            tr["headers"] = {"Host": host}
        return True, tr
    if t == "grpc":
        return True, {"type": "grpc", "service_name": params.get("servicename", "")}
    if t == "httpupgrade":
        tr = {"type": "httpupgrade", "path": path}
        if host:
            tr["host"] = host
        return True, tr
    if t in ("h2", "http"):
        tr = {"type": "http", "path": path}
        if host:
            tr["host"] = [h for h in host.split(",") if h]
        return True, tr
    return False, "транспорт " + t


def build_outbound(entry):
    """Собирает outbound sing-box из записи. None — этот конфиг протестировать нельзя."""
    try:
        scheme, userinfo, params = parse_uri(entry["raw"])
        host = entry["host"]
        port = int(entry["port"])

        if scheme == "vless":
            if params.get("encryption", "none") not in ("", "none"):
                return skip("vless encryption не none")
            ob = {"type": "vless", "server": host, "server_port": port, "uuid": userinfo}
            sec = params.get("security", "none")
            if sec in ("tls", "reality"):
                tls = make_tls(params, host)
                if tls is None:
                    return skip("reality без public key (pbk)")
                ob["tls"] = tls
                if params.get("flow"):
                    ob["flow"] = params["flow"]
            elif sec not in ("none", ""):
                return skip("vless security=" + sec)
            ok, tr = make_transport(params)
            if not ok:
                return skip(tr)
            if tr:
                ob["transport"] = tr
            return ob

        if scheme == "trojan":
            ob = {"type": "trojan", "server": host, "server_port": port, "password": userinfo}
            sec = params.get("security", "tls")
            if sec in ("tls", "reality", ""):
                p = dict(params)
                if sec == "":
                    p["security"] = "tls"
                tls = make_tls(p, host)
                if tls is None:
                    return skip("reality без public key (pbk)")
                ob["tls"] = tls
            elif sec != "none":
                return skip("trojan security=" + sec)
            ok, tr = make_transport(params)
            if not ok:
                return skip(tr)
            if tr:
                ob["transport"] = tr
            return ob

        if scheme in ("hysteria2", "hy2"):
            ob = {"type": "hysteria2", "server": host, "server_port": port, "password": userinfo}
            tls = base_tls(params, host)
            tls.setdefault("alpn", ["h3"])
            ob["tls"] = tls
            obfs = params.get("obfs", "")
            if obfs:
                if obfs != "salamander":
                    return skip("hysteria2 obfs=" + obfs)
                ob["obfs"] = {"type": "salamander", "password": params.get("obfs-password", "")}
            return ob
    except Exception:
        return skip("ошибка разбора ссылки")
    return skip("неизвестная схема")


# =====================================================================
#            ЭТАП 2: запуск sing-box и запросы через SOCKS5
# =====================================================================
def start_singbox(items, base_port):
    """Запускает sing-box с len(items) SOCKS-входами. Возвращает (proc, файлы, текст_ошибки)."""
    cfg = {
        "log": {"level": "warn", "timestamp": False},
        "inbounds": [],
        "outbounds": [],
        "route": {"rules": []},
    }
    for i, (_entry, ob) in enumerate(items):
        ob = dict(ob)
        ob["tag"] = "out-%d" % i
        cfg["outbounds"].append(ob)
        cfg["inbounds"].append({
            "type": "socks", "tag": "in-%d" % i,
            "listen": "127.0.0.1", "listen_port": base_port + i,
        })
        cfg["route"]["rules"].append({"inbound": ["in-%d" % i], "outbound": "out-%d" % i})

    fd_cfg, cfg_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd_cfg, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    fd_err, err_path = tempfile.mkstemp(suffix=".log")
    errf = os.fdopen(fd_err, "w")
    proc = subprocess.Popen([SINGBOX_BIN, "run", "-c", cfg_path], stdout=errf, stderr=errf)
    errf.close()

    files = [cfg_path, err_path]
    last_port = base_port + len(items) - 1
    deadline = time.time() + STARTUP_WAIT
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            socket.create_connection(("127.0.0.1", last_port), timeout=0.5).close()
            return proc, files, ""
        except OSError:
            time.sleep(0.2)

    try:
        with open(err_path, "r", encoding="utf-8", errors="replace") as f:
            err_text = f.read()
    except Exception:
        err_text = ""
    stop_singbox(proc, files)
    return None, None, err_text or "sing-box не запустился"


def stop_singbox(proc, files):
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    for p in files or []:
        try:
            os.remove(p)
        except Exception:
            pass


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise RuntimeError("соединение закрыто")
        data += chunk
    return data


def fetch_via_socks(port, host, path, timeout, stop_after=0):
    """HTTPS GET через локальный SOCKS5 (без внешних библиотек).
    Возвращает dict: status, total_ms, xfer_ms, body."""
    start = time.perf_counter()
    deadline = start + timeout
    conn = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        conn.settimeout(timeout)
        conn.sendall(b"\x05\x01\x00")
        if recv_exact(conn, 2) != b"\x05\x00":
            raise RuntimeError("socks: рукопожатие")
        hb = host.encode()
        conn.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", 443))
        head = recv_exact(conn, 4)
        if head[1] != 0:
            raise RuntimeError("socks: ответ %d" % head[1])
        if head[3] == 1:
            recv_exact(conn, 6)
        elif head[3] == 4:
            recv_exact(conn, 18)
        elif head[3] == 3:
            n = recv_exact(conn, 1)[0]
            recv_exact(conn, n + 2)

        ctx = ssl.create_default_context()
        conn.settimeout(max(0.5, deadline - time.perf_counter()))
        conn = ctx.wrap_socket(conn, server_hostname=host)

        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n" % (path, host)).encode()
        t_req = time.perf_counter()
        conn.sendall(req)

        buf = b""
        total = 0
        header_end = -1
        status = None
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            conn.settimeout(remaining)
            try:
                chunk = conn.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            total += len(chunk)
            if header_end < 0:
                buf += chunk
                idx = buf.find(b"\r\n\r\n")
                if idx >= 0:
                    header_end = idx + 4
                    status = int(buf.split(b" ", 2)[1])
            body = max(0, total - header_end) if header_end >= 0 else 0
            if header_end >= 0 and (status == 204 or (stop_after and body >= stop_after)):
                break
        if status is None:
            raise RuntimeError("нет ответа")
        end = time.perf_counter()
        body = max(0, total - header_end)
        return {
            "status": status,
            "total_ms": (end - start) * 1000,
            "xfer_ms": (end - t_req) * 1000,
            "body": body,
        }
    finally:
        try:
            conn.close()
        except Exception:
            pass


def test_one(port):
    """Реальный тест одного конфига через его SOCKS-порт. (real_ms, speed_kbps) или None."""
    real_ms = None
    for host, path in LATENCY_TARGETS:
        try:
            r = fetch_via_socks(port, host, path, REAL_TIMEOUT)
        except Exception:
            continue
        if r["status"] in (200, 204):
            real_ms = int(r["total_ms"])
            break
    if real_ms is None or real_ms > MAX_REAL_MS:
        return None

    speed = None
    try:
        r = fetch_via_socks(port, SPEED_TARGET[0], SPEED_TARGET[1], SPEED_TIMEOUT, stop_after=SPEED_BYTES)
        if r["status"] == 200 and r["body"] > 0:
            speed = int(r["body"] / 1024 / max(r["xfer_ms"] / 1000.0, 0.05))
    except Exception:
        speed = None  # скорость не измерилась — не наказываем сервер
    if speed is not None and speed < MIN_SPEED_KBPS:
        return None
    return real_ms, speed


def process_items(items, base_port, stats):
    """Запускает sing-box для пачки и проверяет все конфиги. Если пачка не стартует из-за
    одного битого конфига — находит его (по номеру из ошибки или делением пополам)."""
    if not items:
        return
    proc, files, err = start_singbox(items, base_port)
    if proc is None:
        m = re.search(r"outbounds?\[(\d+)\]", err)
        if m and int(m.group(1)) < len(items):
            stats["invalid"] += 1
            idx = int(m.group(1))
            process_items(items[:idx] + items[idx + 1:], base_port, stats)
            return
        if len(items) == 1:
            stats["invalid"] += 1
            return
        mid = len(items) // 2
        process_items(items[:mid], base_port, stats)
        process_items(items[mid:], base_port, stats)
        return

    try:
        stats["tested"] += len(items)
        for _e, _ob in items:
            TESTED_KEYS.add(entry_key(_e))
        with cf.ThreadPoolExecutor(max_workers=BATCH_WORKERS) as ex:
            futs = {}
            for i, (entry, _ob) in enumerate(items):
                futs[ex.submit(test_one, base_port + i)] = entry
            for fut in cf.as_completed(futs):
                entry = futs[fut]
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if res:
                    entry["real_ms"], entry["speed_kbps"] = res
                    stats["passed"] += 1
    finally:
        stop_singbox(proc, files)


def real_test(candidates):
    stats = {"unsupported": 0, "invalid": 0, "tested": 0, "passed": 0}
    t0 = time.time()
    for b in range(0, len(candidates), BATCH_SIZE):
        if time.time() - t0 > TIME_BUDGET_SEC:
            print("⏱ Бюджет времени исчерпан, остальные конфиги не проверялись.")
            break
        items = []
        for e in candidates[b:b + BATCH_SIZE]:
            ob = build_outbound(e)
            if ob is None:
                stats["unsupported"] += 1
            else:
                items.append((e, ob))
        base_port = BASE_PORT + ((b // BATCH_SIZE) % 20) * 500
        process_items(items, base_port, stats)
        print("  пачка %d: проверено %d, прошли %d" % (b // BATCH_SIZE + 1, stats["tested"], stats["passed"]))
    passed = [e for e in candidates if e.get("real_ms") is not None]
    return passed, stats


# =====================================================================
#                          ИСТОРИЯ ПРОВЕРЕННЫХ СЕРВЕРОВ
# =====================================================================
def entry_key(e):
    return "%s:%s" % (str(e.get("host", "")).lower(), e.get("port"))


def load_history():
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_history(history):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, separators=(",", ":"))
    except Exception as e:
        print("История не сохранена: %s" % e)


def inject_history(configs, history):
    """Добавляет серверы из истории во вход этапа 1 (если их там ещё нет).
    Возвращает (конфиги, ключи приоритетных серверов, сколько добавлено)."""
    present = {entry_key(e) for e in configs}
    items = sorted(history.items(),
                   key=lambda kv: (kv[1].get("ok", 0), kv[1].get("last_ok", 0)), reverse=True)
    injected, hist_keys = [], set()
    for k, v in items:
        if len(hist_keys) >= HISTORY_INJECT:
            break
        if "entry" not in v:
            continue
        hist_keys.add(k)
        if k not in present:
            injected.append(json.loads(json.dumps(v["entry"])))
            present.add(k)
    return configs + injected, hist_keys, len(injected)


def note_stage1_failures(history, hist_keys, quick):
    """Серверы из истории, не прошедшие быстрый отсев, считаются провалом."""
    alive = {entry_key(e) for e in quick}
    for k in hist_keys:
        if k not in alive and k in history:
            history[k]["fail"] = history[k].get("fail", 0) + 1
            history[k]["ok"] = 0


def update_history(history, tested_keys, passed, now):
    pass_map = {entry_key(e): e for e in passed}
    for k in tested_keys:
        if k in pass_map:
            v = history.get(k) or {"ok": 0, "fail": 0, "total_ok": 0}
            v["ok"] = v.get("ok", 0) + 1
            v["fail"] = 0
            v["total_ok"] = v.get("total_ok", 0) + 1
            v["last_ok"] = now
            v["entry"] = dict(pass_map[k])
            history[k] = v
        elif k in history:
            history[k]["fail"] = history[k].get("fail", 0) + 1
            history[k]["ok"] = 0


def carried_over(history, passed):
    """Серверы, которые часто проходили и лишь один раз подряд сбойнули: оставляем в пуле."""
    have = {entry_key(e) for e in passed}
    out = []
    for k, v in history.items():
        if k in have or "entry" not in v:
            continue
        if v.get("fail", 0) == 1 and v.get("total_ok", 0) >= HISTORY_GRACE_MIN_OK:
            out.append(json.loads(json.dumps(v["entry"])))
    return out


def prune_history(history, now):
    cutoff = now - HISTORY_MAX_AGE_DAYS * 86400
    for k in list(history):
        v = history[k]
        if "entry" not in v or v.get("fail", 0) >= HISTORY_MAX_FAILS or v.get("last_ok", 0) < cutoff:
            del history[k]
    if len(history) > HISTORY_MAX_ENTRIES:
        keep = sorted(history, key=lambda k: (history[k].get("ok", 0), history[k].get("last_ok", 0)),
                      reverse=True)[:HISTORY_MAX_ENTRIES]
        history = {k: history[k] for k in keep}
    return history


def pick_candidates(quick, hist_keys=frozenset()):
    """Выбирает конфиги для реального теста (см. описание в начале файла).
    quick уже отсортирован по ping_ms. Серверы из истории идут первыми."""
    rng = random.Random()
    priority = [e for e in quick if entry_key(e) in hist_keys][:HISTORY_INJECT]
    pri_keys = {entry_key(e) for e in priority}
    pool = [e for e in quick if entry_key(e) not in pri_keys]
    hy2 = [e for e in pool if e.get("proto") == "hysteria2"]
    other = [e for e in pool if e.get("proto") != "hysteria2"]
    reality = [e for e in other if e.get("security_tag") == "reality"]
    plain = [e for e in other if e.get("security_tag") != "reality"]

    hy2_pick = hy2[:HY2_CAP]
    reality_pick = rng.sample(reality, min(len(reality), REALITY_CAP))
    fast_pick = plain[:FAST_CAP]
    rest = plain[FAST_CAP:]
    random_pick = rng.sample(rest, min(len(rest), RANDOM_CAP))

    print("Выборка для этапа 2: из истории %d, Hysteria2 %d (из %d), Reality %d (из %d), "
          "vless/trojan по пингу %d + случайных %d (из %d)"
          % (len(priority), len(hy2_pick), len(hy2), len(reality_pick), len(reality),
             len(fast_pick), len(random_pick), len(plain)))
    return priority + hy2_pick + reality_pick + fast_pick + random_pick


# =====================================================================
def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    use_history = REAL_TEST_ENABLED and os.path.exists(SINGBOX_BIN)
    history, hist_keys = {}, set()
    if use_history:
        history = load_history()
        configs, hist_keys, n_injected = inject_history(configs, history)
        print("История: записей %d, из них добавлено в проверку %d" % (len(history), n_injected))

    print("Этап 1: быстрый отсев %d серверов (порог %d мс)..." % (len(configs), MAX_PING_MS))
    quick = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for res in ex.map(quick_check, configs):
            if res:
                quick.append(res)
    quick.sort(key=lambda e: e["ping_ms"])
    print("Этап 1 пройден: %d из %d" % (len(quick), len(configs)))
    if use_history:
        note_stage1_failures(history, hist_keys, quick)

    final = quick
    if not REAL_TEST_ENABLED:
        print("Реальный тест выключен (REAL_TEST=0) — используем результат этапа 1.")
    elif not os.path.exists(SINGBOX_BIN):
        print("⚠️ sing-box не найден (%s) — используем результат этапа 1." % SINGBOX_BIN)
    else:
        candidates = pick_candidates(quick, hist_keys)
        print("Этап 2: реальный тест через sing-box для %d серверов..." % len(candidates))
        passed, stats = real_test(candidates)
        print("Этап 2: проверено %(tested)d, прошли %(passed)d, не поддерживается %(unsupported)d, "
              "битых конфигов %(invalid)d" % stats)
        for reason, n in UNSUPPORTED.most_common():
            print("  не поддерживается: %s — %d" % (reason, n))
        if not passed and len(candidates) >= 20:
            print("⚠️ Реальный тест не пропустил НИ ОДНОГО сервера — похоже, сломан сам тест. "
                  "Используем результат этапа 1, чтобы подписка не опустела.")
        else:
            passed.sort(key=lambda e: e["real_ms"])
            final = passed
            if use_history:
                now = int(time.time())
                update_history(history, TESTED_KEYS, passed, now)
                extra = carried_over(history, passed)
                if extra:
                    print("История: оставлено после единичного сбоя: %d" % len(extra))
                    final = sorted(passed + extra, key=lambda e: e.get("real_ms", 9999))
                history = prune_history(history, now)
                save_history(history)
                print("История: сохранено записей %d" % len(history))

    hy2_count = sum(1 for e in final if e.get("proto") == "hysteria2")
    print("Итого в pinged_configs.json: %d (из них Hysteria2: %d)" % (len(final), hy2_count))

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
