#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
filter_clean.py
Чистит raw_configs.json:
 - оставляет только vless / trojan / hysteria2 (hy2)
 - выкидывает WARP, Tor/onion, явный мусор и "сомнительные" ноды (bns и т.п.)
 - дедуплицирует по host:port (а не по всей строке — так убираем клонов с разным именем)
Результат: clean_configs.json — список dict{proto, host, port, raw, remark}
"""
import json
import os
import re
import urllib.parse

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "raw_configs.json")
OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "clean_configs.json")

BAD_KEYWORDS = [
    "warp", "wireguard", "tor", "onion", "bns", "test", "expired",
    "истек", "не работает", "fake", "demo", "sample", "invalid",
    "cloudflare-warp", "1.1.1.1",
]

ALLOWED_PROTO = {"vless", "trojan", "hysteria2", "hy2"}


def parse_config(raw):
    try:
        proto = raw.split("://", 1)[0].lower()
        if proto not in ALLOWED_PROTO:
            return None

        rest = raw.split("://", 1)[1]
        remark = ""
        if "#" in rest:
            rest, frag = rest.split("#", 1)
            remark = urllib.parse.unquote(frag)

        hostport_part = rest
        if "@" in rest:
            hostport_part = rest.split("@", 1)[1]
        query_part = ""
        if "?" in hostport_part:
            hostport_part, query_part = hostport_part.split("?", 1)
        hostport_part = hostport_part.split("/", 1)[0]

        m = re.match(r"^\[?([^\]/:]+)\]?:(\d+)$", hostport_part)
        if not m:
            return None
        host, port = m.group(1), int(m.group(2))

        params = dict(urllib.parse.parse_qsl(query_part))
        is_reality = params.get("security", "").lower() == "reality"

        return {
            "proto": "hysteria2" if proto == "hy2" else proto,
            "security_tag": "reality" if is_reality else params.get("security", ""),
            "host": host,
            "port": port,
            "remark": remark,
            "raw": raw,
        }
    except Exception:
        return None


def is_bad(entry):
    haystack = f"{entry['remark']} {entry['host']}".lower()
    return any(kw in haystack for kw in BAD_KEYWORDS)


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        raw_list = json.load(f)

    parsed = []
    for raw in raw_list:
        entry = parse_config(raw)
        if entry is None:
            continue
        if is_bad(entry):
            continue
        parsed.append(entry)

    seen = set()
    unique = []
    for e in parsed:
        key = (e["host"], e["port"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(e)

    reality_count = sum(1 for e in unique if e.get("security_tag") == "reality")
    print(f"Было: {len(raw_list)} -> валидных: {len(parsed)} -> уникальных host:port: {len(unique)}")
    print(f"Из них с Reality (security=reality): {reality_count}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
