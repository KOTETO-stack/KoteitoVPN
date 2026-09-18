#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns_test.py
Проверяет, что host сервера резолвится и не указывает на приватный/локальный
диапазон (типичный признак битого конфига). Проставляет remote_dns-подсказку.
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


def resolve_ok(host):
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip_str = info[4][0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        return len(infos) > 0
    except Exception:
        return False


def check(entry):
    if resolve_ok(entry["host"]):
        entry["remote_dns"] = RECOMMENDED_DOH
        return entry
    return None


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    results = []
    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        for res in ex.map(check, configs):
            if res:
                results.append(res)

    print(f"DNS-проверка пройдена: {len(results)} из {len(configs)}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
