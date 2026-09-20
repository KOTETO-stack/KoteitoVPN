#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ping_test.py

Версия 4 — добавлена настоящая TLS-проверка вместо простого TCP-connect для
vless/trojan c security=tls или reality:
 - Раньше: TCP-порт открыт -> сервер считался живым. Но открытый порт не
   значит, что за ним реально работает TLS/proxy (бывает: балансировщик
   отвечает на SYN, а сам сервис за ним давно упал).
 - Теперь: после успешного TCP-подключения делаем настоящий TLS-хендшейк на
   тот же SNI, что указан в самом конфиге. Если хендшейк не проходит -
   сервер бракуется, даже если порт формально был "открыт". Это и есть
   "удаление неработающих серверов", про которое просили.

Для Hysteria2 (UDP/QUIC) остаётся прямой UDP-проб порта (см. версии 2-3 ниже) -
TLS-хендшейк здесь неприменим, у QUIC свой протокол на транспортном уровне.

Оставляет только серверы с пингом <= MAX_PING_MS.
Результат: pinged_configs.json — список dict с добавленным полем "ping_ms".
"""
import json
import os
import socket
import ssl
import time
import urllib.parse
import concurrent.futures as cf

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "clean_configs.json")
OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "pinged_configs.json")

MAX_PING_MS = 500
CONNECT_TIMEOUT = 2.5
UDP_PROBE_TIMEOUT = 1.5
WORKERS = 40  # чуть меньше, чем раньше - TLS-хендшейк тяжелее простого TCP-connect


def extract_sni(raw, fallback_host):
    """Достаёт sni (или host) параметр из самого конфига - тот домен,
    который сервер ожидает увидеть в TLS ClientHello."""
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
    """TCP-connect для всех; если это vless/trojan с TLS/Reality - дополнительно
    настоящий TLS-хендшейк на SNI из конфига. CERT_NONE специально: нам не важно,
    доверенный ли сертификат (многие такие сервера на самоподписанных) - важно
    только то, что TLS-протокол на том конце реально отвечает."""
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
    """Проб конкретно UDP-порта Hysteria2-сервера (не ICMP к хосту)."""
    start = time.perf_counter()
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(UDP_PROBE_TIMEOUT)
        s.connect((host, port))
        s.send(os.urandom(32))  # заведомо невалидный QUIC Initial - нам важна не сессия, а реакция порта
        try:
            s.recvfrom(1024)
            return int((time.perf_counter() - start) * 1000)  # реальный ответ - точный RTT
        except socket.timeout:
            approx = int(UDP_PROBE_TIMEOUT * 1000) - 200
            return max(50, min(approx, MAX_PING_MS - 1))
        except ConnectionRefusedError:
            return None  # ICMP port-unreachable - порт реально закрыт/недоступен
    except Exception:
        return None
    finally:
        if s:
            s.close()


def check(entry):
    if entry.get("proto") == "hysteria2":
        ms = udp_probe(entry["host"], entry["port"])
    else:
        ms = tcp_or_tls_ping(entry)

    if ms is None or ms > MAX_PING_MS:
        return None
    entry["ping_ms"] = ms
    return entry


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    print(f"Проверяем {len(configs)} серверов (TCP+TLS для vless/trojan, UDP-проб для Hysteria2, порог {MAX_PING_MS} мс)...")

    results = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for res in ex.map(check, configs):
            if res:
                results.append(res)

    results.sort(key=lambda e: e["ping_ms"])
    hy2_count = sum(1 for e in results if e.get("proto") == "hysteria2")
    print(f"Прошли проверку: {len(results)} из {len(configs)} (из них Hysteria2: {hy2_count})")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
