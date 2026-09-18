#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_subscription.py
Финальный шаг workflow №2: лимит 150, русские имена, base64 в output/subscription.txt.
"""
import base64
import json
import os
import urllib.parse

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "masked_configs.json")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
OUT_SUB = os.path.join(OUT_DIR, "subscription.txt")
OUT_READABLE = os.path.join(OUT_DIR, "subscription_readable.txt")

MAX_SERVERS = 150


def rename_uri(raw: str, display_name: str) -> str:
    base = raw.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(display_name)}"


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    configs.sort(key=lambda c: c.get("ping_ms", 9999))
    configs = configs[:MAX_SERVERS]

    final_lines = []
    for c in configs:
        display_name = c.get("display_name") or c.get("remark") or "VPN"
        final_lines.append(rename_uri(c["raw"], display_name))

    body = "\n".join(final_lines)

    with open(OUT_READABLE, "w", encoding="utf-8") as f:
        f.write(body + "\n")

    encoded = base64.b64encode(body.encode("utf-8")).decode("utf-8")
    with open(OUT_SUB, "w", encoding="utf-8") as f:
        f.write(encoded)

    print(f"В финальную подписку вошло {len(final_lines)} серверов (лимит {MAX_SERVERS}).")
    print(f"Файл подписки: {OUT_SUB}")


if __name__ == "__main__":
    main()
