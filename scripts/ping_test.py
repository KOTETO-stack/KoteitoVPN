#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ping_test.py
TCP-connect пинг (ICMP на раннерах GitHub Actions обычно недоступен без root).
Оставляет только серверы с пингом <= MAX_PING_MS.
Результат: pinged_configs.json — список dict с полем "ping_ms".
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
WORKERS = 60


def tcp_ping(host, port):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            pass
        return int((time.perf_counter() - start) * 1000)
    except Exception:
        return None


def check(entry):
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
    print(f"Прошли проверку пинга: {len(results)} из {len(configs)}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
