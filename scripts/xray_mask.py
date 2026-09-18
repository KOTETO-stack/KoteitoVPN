#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xray_mask.py
uTLS fingerprint (fp=chrome) + нормализация WS host/path. SNI не подменяется
на произвольный домен - только если он уже стоял в исходном конфиге.
Результат: masked_configs.json
"""
import json
import os
import urllib.parse

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "geo_configs.json")
OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "masked_configs.json")


def mask_uri(raw: str) -> str:
    proto, rest = raw.split("://", 1)
    remark = ""
    if "#" in rest:
        rest, remark = rest.split("#", 1)

    if "?" in rest:
        head, query_str = rest.split("?", 1)
    else:
        head, query_str = rest, ""

    params = dict(urllib.parse.parse_qsl(query_str, keep_blank_values=True))

    security = params.get("security", "").lower()
    has_tls = security in ("tls", "reality") or proto.lower() == "hysteria2"

    if has_tls and "fp" not in params:
        params["fp"] = "chrome"

    net = params.get("type", "").lower()
    if net == "ws":
        params.setdefault("path", "/api/v1/stream")
        if not params.get("host"):
            params["host"] = params.get("sni", "")

    new_query = urllib.parse.urlencode(params, safe=":/")
    new_rest = head + ("?" + new_query if new_query else "")
    return f"{proto}://{new_rest}#{remark}" if remark else f"{proto}://{new_rest}"


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    for c in configs:
        try:
            c["raw"] = mask_uri(c["raw"])
        except Exception:
            pass

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(configs, f, ensure_ascii=False, indent=2)

    print(f"Замаскировано конфигов: {len(configs)}")


if __name__ == "__main__":
    main()
