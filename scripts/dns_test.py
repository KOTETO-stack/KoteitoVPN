#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns_test.py
1. Проверяет, что host сервера резолвится (не мёртвый/заглушка).
2. Отбраковывает серверы с приватным/локальным IP.
3. Проставляет remote_dns.
4. Дедуплицирует по РЕАЛЬНОМУ IP:port, а не только по домену.
Результат: dns_checked_configs.json
"""
import ipaddress
import json
import os
import socket
import concurrent.futures as cf

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "pinged_configs.json")
OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "dns_checked_configs.json")

RECOMMENDED_DOH = "https://dns.adguard-dns.com/dns-query"


def resolve_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return None if (ip.is_private or ip.is_loopback or ip.is_link_local) else host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip_str = info[4][0]
            ip = ipaddress.ip_address(ip_str)
            if not (ip.is_private or ip.is_loopback or ip.is_link_local):
                return ip_str
        return None
    except Exception:
        return None


def check(entry):
    ip = resolve_ip(entry["host"])
    if not ip:
        return None
    entry["resolved_ip"] = ip
    entry["remote_dns"] = RECOMMENDED_DOH
    return entry


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    resolved = []
    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        for res in ex.map(check, configs):
            if res:
                resolved.append(res)

    print(f"DNS-проверка пройдена: {len(resolved)} из {len(configs)}")

    resolved.sort(key=lambda e: e.get("ping_ms", 9999))
    seen_ip_port = set()
    results = []
    duplicates_removed = 0
    for entry in resolved:
        key = (entry["resolved_ip"], entry["port"])
        if key in seen_ip_port:
            duplicates_removed += 1
            continue
        seen_ip_port.add(key)
        results.append(entry)

    if duplicates_removed:
        print(f"Убрано дублей по реальному IP: {duplicates_removed}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
