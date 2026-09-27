#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import json
import os
import re
import urllib.parse
from datetime import datetime, timedelta, timezone

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "masked_configs.json")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
OUT_SUB = os.path.join(OUT_DIR, "subscription.txt")
OUT_READABLE = os.path.join(OUT_DIR, "subscription_readable.txt")
OUT_SUB_CELLULAR = os.path.join(OUT_DIR, "subscription_cellular.txt")
OUT_READABLE_CELLULAR = os.path.join(OUT_DIR, "subscription_cellular_readable.txt")
REPORTS_FILE = os.path.join(OUT_DIR, "server_reports.json")

MAX_SERVERS = 200
REALITY_BONUS_MS = 50
TRANSPORT_BONUS_MS = 20
CELLULAR_BONUS_MS = 80
STABLE_TRANSPORTS = {"xhttp", "grpc", "ws"}
MAX_PER_COUNTRY = 10
EXCLUDED_COUNTRIES = {"RU"}
CELLULAR_EXCLUDED_PROTOCOLS = {"hysteria2"}

REPORT_BONUS_MS = 150
REPORT_TTL_HOURS = 48

TYPE_RE = re.compile(r"[?&]type=([a-zA-Z0-9_-]+)", re.IGNORECASE)


def load_reports():
    if not os.path.exists(REPORTS_FILE):
        return {}
    try:
        with open(REPORTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def is_confirmed(display_name, reports, now):
    entry = reports.get(display_name)
    if not entry or not entry.get("last_ok"):
        return False
    try:
        last_ok = datetime.fromisoformat(entry["last_ok"])
    except (ValueError, TypeError):
        return False
    if (now - last_ok) > timedelta(hours=REPORT_TTL_HOURS):
        return False
    last_fail_raw = entry.get("last_fail")
    if last_fail_raw:
        try:
            last_fail = datetime.fromisoformat(last_fail_raw)
            if last_fail > last_ok:
                return False
        except (ValueError, TypeError):
            pass
    return True


def rename_uri(raw: str, display_name: str) -> str:
    base = raw.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(display_name)}"


def extract_transport(raw: str) -> str:
    m = TYPE_RE.search(raw)
    return m.group(1).lower() if m else ""


def make_sort_key(reports, now):
    def sort_key(c):
        ping = c.get("ping_ms", 9999)
        bonus = REALITY_BONUS_MS if c.get("security_tag") == "reality" else 0
        if extract_transport(c.get("raw", "")) in STABLE_TRANSPORTS:
            bonus += TRANSPORT_BONUS_MS
        if c.get("proto") != "hysteria2":
            bonus += CELLULAR_BONUS_MS

        display_name = c.get("display_name") or c.get("remark") or "VPN"
        if is_confirmed(display_name, reports, now):
            bonus += REPORT_BONUS_MS

        return ping - bonus
    return sort_key


def select_with_quota(configs, sort_key, exclude_protocols=frozenset()):
    configs = [c for c in configs if c.get("country_code", "??") not in EXCLUDED_COUNTRIES]
    configs = [c for c in configs if c.get("proto") not in exclude_protocols]
    configs = sorted(configs, key=sort_key)

    country_count = {}
    selected = []

    for c in configs:
        if len(selected) >= MAX_SERVERS:
            break
        cc = c.get("country_code", "??")
        if country_count.get(cc, 0) >= MAX_PER_COUNTRY:
            continue
        selected.append(c)
        country_count[cc] = country_count.get(cc, 0) + 1

    return selected


def render_subscription(configs, reports, now, out_sub, out_readable, label):
    final_lines = []
    for c in configs:
        display_name = c.get("display_name") or c.get("remark") or "VPN"
        original_name = display_name

        if is_confirmed(original_name, reports, now):
            display_name = f"{display_name} \u2705"

        final_lines.append(rename_uri(c["raw"], display_name))

    body = "\n".join(final_lines)

    with open(out_readable, "w", encoding="utf-8") as f:
        f.write(body + "\n")

    encoded = base64.b64encode(body.encode("utf-8")).decode("utf-8")
    with open(out_sub, "w", encoding="utf-8") as f:
        f.write(encoded)

    reality_count = sum(1 for c in configs if c.get("security_tag") == "reality")
    hy2_count = sum(1 for c in configs if c.get("proto") == "hysteria2")
    stable_transport_count = sum(
        1 for c in configs if extract_transport(c.get("raw", "")) in STABLE_TRANSPORTS
    )
    confirmed_count = sum(
        1 for c in configs
        if is_confirmed(c.get("display_name") or c.get("remark") or "VPN", reports, now)
    )
    countries_count = len({c.get("country_code", "??") for c in configs})
    print(f"[{label}] вошло {len(final_lines)} серверов (лимит {MAX_SERVERS}), "
          f"из них Reality: {reality_count}, Hysteria2: {hy2_count}, "
          f"стабильные транспорты (xhttp/grpc/ws): {stable_transport_count}, "
          f"подтверждено пользователями: {confirmed_count}, "
          f"стран: {countries_count} (лимит {MAX_PER_COUNTRY} на страну).")
    print(f"[{label}] файл: {out_sub}")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    reports = load_reports()
    now = datetime.now(timezone.utc)
    sort_key = make_sort_key(reports, now)

    main_selected = select_with_quota(configs, sort_key)
    render_subscription(main_selected, reports, now, OUT_SUB, OUT_READABLE, "основная")

    cellular_selected = select_with_quota(configs, sort_key, exclude_protocols=CELLULAR_EXCLUDED_PROTOCOLS)
    render_subscription(cellular_selected, reports, now, OUT_SUB_CELLULAR, OUT_READABLE_CELLULAR, "мобильная")


if __name__ == "__main__":
    main()
