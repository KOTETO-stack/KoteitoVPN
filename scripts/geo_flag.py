#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
geo_flag.py
Определяет страну/город сервера через ip-api.com (lang=ru). Флаг эмодзи строится
математически из ISO alpha-2 кода. Исключает Украину. Fallback-провайдер: ipwho.is.
Результат: geo_configs.json
"""
import ipaddress
import json
import os
import socket
import time
import urllib.request

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "dns_checked_configs.json")
OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "geo_configs.json")

BATCH_URL = "http://ip-api.com/batch?lang=ru&fields=status,countryCode,country,city,query"
BATCH_SIZE = 100
RATE_SLEEP_SEC = 4.2
EXCLUDED_COUNTRY_CODES = {"UA"}


def flag_emoji(country_code: str) -> str:
    cc = country_code.upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(ord(c) - ord("A") + 0x1F1E6) for c in cc)


def resolve_ip(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except Exception:
            return None


def geo_lookup_batch(ips):
    body = json.dumps(ips).encode("utf-8")
    req = urllib.request.Request(
        BATCH_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def geo_lookup_fallback(ip):
    try:
        req = urllib.request.Request(
            f"https://ipwho.is/{ip}", headers={"User-Agent": "KoteitoVPN-geo-fallback"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if not data.get("success", True) is False and data.get("country_code"):
            return {
                "status": "success",
                "countryCode": data.get("country_code", ""),
                "country": data.get("country", ""),
                "city": data.get("city", ""),
            }
    except Exception as e:
        print(f"[fallback geo error] {ip} -> {e}")
    return None


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    for c in configs:
        c["_ip"] = resolve_ip(c["host"])

    resolvable = [c for c in configs if c["_ip"]]
    print(f"Резолвится в IP: {len(resolvable)} из {len(configs)}")

    results = []
    for i in range(0, len(resolvable), BATCH_SIZE):
        batch = resolvable[i : i + BATCH_SIZE]
        ips = [c["_ip"] for c in batch]
        try:
            geo = geo_lookup_batch(ips)
        except Exception as e:
            print(f"[geo batch error] {e} -> fallback")
            geo = [geo_lookup_fallback(ip) for ip in ips]

        for entry, g in zip(batch, geo):
            if not g or g.get("status") != "success":
                g = geo_lookup_fallback(entry["_ip"])
                if not g:
                    continue
            cc = g.get("countryCode", "")
            if not cc or cc in EXCLUDED_COUNTRY_CODES:
                continue
            entry["country_ru"] = g.get("country", "").strip()
            entry["city_ru"] = (g.get("city") or "").strip()
            entry["flag"] = flag_emoji(cc)
            entry["country_code"] = cc
            parts = [p for p in [entry["country_ru"], entry["city_ru"], entry["flag"]] if p]
            entry["display_name"] = " ".join(parts)
            results.append(entry)

        if i + BATCH_SIZE < len(resolvable):
            time.sleep(RATE_SLEEP_SEC)

    print(f"С определённой страной (без Украины): {len(results)}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
