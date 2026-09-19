#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ping_test.py
Для Hysteria2 (UDP/QUIC) обычный TCP-connect всегда проваливается, поэтому для
него делаем прямой UDP-проб порта сервера:
 - есть ответ - точный RTT
 - явный ConnectionRefusedError (ICMP port-unreachable) - порт закрыт, бракуем
 - тишина (обычная реакция QUIC на невалидный пакет) - считаем живым

Оставляет только серверы с пингом <= MAX_PING_MS.
Результат: pinged_configs.json — список dict с добавленным полем "ping_ms".
"""
import json
import os
import socket
import time
import concurrent.futures as cf

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "clean_configs.json")
OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "pinged_configs.json")

MAX_PING_MS = 500
CONNECT_TIMEOUT = 2.5
UDP_PROBE_TIMEOUT = 1.5
WORKERS = 50


def tcp_ping(host, port):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            pass
        return int((time.perf_counter() - start) * 1000)
    except Exception:
        return None


def udp_probe(host, port):
    """Проб конкретно UDP-порта Hysteria2-сервера (не ICMP к хосту)."""
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


def check(entry):
    if entry.get("proto") == "hysteria2":
        ms = udp_probe(entry["host"], entry["port"])
    else:
        ms = tcp_ping(entry["host"], entry["port"])

    if ms is None or ms > MAX_PING_MS:
        return None
    entry["ping_ms"] = ms
    return entry


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    print(f"Проверяем пинг для {len(configs)} серверов (порог {MAX_PING_MS} мс)...")

    results = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for res in ex.map(check, configs):
            if res:
                results.append(res)

    results.sort(key=lambda e: e["ping_ms"])
    hy2_count = sum(1 for e in results if e.get("proto") == "hysteria2")
    print(f"Прошли проверку пинга: {len(results)} из {len(configs)} (из них Hysteria2: {hy2_count})")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
