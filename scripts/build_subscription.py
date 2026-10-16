#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_subscription.py
Финальный шаг workflow. Собирает ДВЕ подписки из одного пула конфигов:

 1. output/subscription.txt — основная. Лучшие серверы по sort_key.
 2. output/subscription_cellular.txt — вторая. Те же правила отбора, но
    только серверы, которых НЕТ в основной подписке.

Обе подписки:
 - исключают серверы с country_code из EXCLUDED_COUNTRIES (Россия)
 - сортируют по пингу с бонусами для Reality, стабильных транспортов
   (XHTTP/gRPC/WS), TCP-протоколов и подтверждённых пользователями серверов
 - учитывают давление блокировок по данным OONI (если файл есть)
 - не дают одной стране занять больше MAX_PER_COUNTRY мест
 - берут не больше MAX_SERVERS
 - округляют количество до ближайшего десятка сверху
 - переименовывают remark в "Страна Город Флаг", подтверждённые помечаются "✅"
 - кодируются в base64 (формат подписки Karing/Hiddyfi/v2rayNG)
"""
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
OONI_INDEX_FILE = os.path.join(OUT_DIR, "ooni_censorship_index.json")

OONI_PRESSURE_THRESHOLD = 50          # % — выше этого порога давление считается высоким
OONI_HIGH_PRESSURE_MULTIPLIER = 1.5   # во столько раз усиливаем бонусы при высоком давлении

MAX_SERVERS = 200
REALITY_BONUS_MS = 50
TRANSPORT_BONUS_MS = 20               # для type=xhttp/grpc/ws
CELLULAR_BONUS_MS = 80                # бонус TCP-протоколам (vless/trojan)
STABLE_TRANSPORTS = {"xhttp", "grpc", "ws"}
MAX_PER_COUNTRY = 20
EXCLUDED_COUNTRIES = {"RU"}           # серверы внутри России не помогают обходить блокировки РКН

REPORT_BONUS_MS = 150                 # подтверждённый человеком сервер важнее
REPORT_TTL_HOURS = 48                 # сколько часов подтверждение актуально

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
    """True, если есть подтверждение "работает" не старше REPORT_TTL_HOURS
    и оно не было позже отменено сообщением "-Имя сервера"."""
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


def load_ooni_pressure():
    """Читает output/ooni_censorship_index.json. Возвращает процент давления
    блокировок (0-100) или None, если данных нет."""
    if not os.path.exists(OONI_INDEX_FILE):
        return None
    try:
        with open(OONI_INDEX_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("pressure_percent")
    except (json.JSONDecodeError, OSError):
        return None


def rename_uri(raw: str, display_name: str) -> str:
    base = raw.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(display_name)}"


def extract_transport(raw: str) -> str:
    m = TYPE_RE.search(raw)
    return m.group(1).lower() if m else ""


def make_sort_key(reports, now):
    pressure = load_ooni_pressure()
    high_pressure = pressure is not None and pressure >= OONI_PRESSURE_THRESHOLD
    multiplier = OONI_HIGH_PRESSURE_MULTIPLIER if high_pressure else 1
    reality_bonus = REALITY_BONUS_MS * multiplier
    cellular_bonus = CELLULAR_BONUS_MS * multiplier
    if pressure is not None:
        print(f"Индикатор давления блокировок OONI (РФ): {pressure}% "
              f"({'высокое, бонусы усилены' if high_pressure else 'в норме'})")

    def sort_key(c):
        ping = c.get("ping_ms", 9999)
        bonus = reality_bonus if c.get("security_tag") == "reality" else 0
        if extract_transport(c.get("raw", "")) in STABLE_TRANSPORTS:
            bonus += TRANSPORT_BONUS_MS
        if c.get("proto") != "hysteria2":
            bonus += cellular_bonus

        display_name = c.get("display_name") or c.get("remark") or "VPN"
        if is_confirmed(display_name, reports, now):
            bonus += REPORT_BONUS_MS

        return ping - bonus
    return sort_key


def select_with_quota(configs, sort_key):
    """Топ MAX_SERVERS по sort_key с лимитом MAX_PER_COUNTRY на страну."""
    configs = [c for c in configs if c.get("country_code", "??") not in EXCLUDED_COUNTRIES]
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


def round_up_to_ten(selected, configs, sort_key):
    """Дополняет список до ближайшего круглого десятка сверху. Добивка берётся
    из лучших кандидатов, которые не вошли в основной отбор, без лимита на страну."""
    target = -(-len(selected) // 10) * 10
    if target == len(selected) or target == 0:
        return selected

    pool = [c for c in configs if c.get("country_code", "??") not in EXCLUDED_COUNTRIES]
    pool = sorted(pool, key=sort_key)

    selected_raws = {c["raw"] for c in selected}
    result = list(selected)
    for c in pool:
        if len(result) >= target:
            break
        if c["raw"] in selected_raws:
            continue
        result.append(c)
        selected_raws.add(c["raw"])
    return result


def render_subscription(configs, reports, now, out_sub, out_readable, label):
    final_lines = []
    for c in configs:
        display_name = c.get("display_name") or c.get("remark") or "VPN"
        if is_confirmed(display_name, reports, now):
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

    # 1. Основная подписка
    main_base = select_with_quota(configs, sort_key)
    main_selected = round_up_to_ten(main_base, configs, sort_key)
    render_subscription(main_selected, reports, now, OUT_SUB, OUT_READABLE, "основная")

    # 2. Вторая подписка: те же правила, но только серверы, которых нет в основной
    used_raw = {c["raw"] for c in main_selected}
    remainder = [c for c in configs if c["raw"] not in used_raw]

    alt_base = select_with_quota(remainder, sort_key)
    alt_selected = round_up_to_ten(alt_base, remainder, sort_key)
    render_subscription(alt_selected, reports, now, OUT_SUB_CELLULAR, OUT_READABLE_CELLULAR, "вторая")


if __name__ == "__main__":
    main()
