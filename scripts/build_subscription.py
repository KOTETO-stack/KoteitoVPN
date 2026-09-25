#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_subscription.py
Финальный шаг workflow №2:
 - исключает серверы с country_code из EXCLUDED_COUNTRIES (по умолчанию
   Россия — сервер внутри РФ не помогает обойти блокировки РКН, см. пояснение)
 - сортирует по пингу с бонусами для Reality и для "стабильных" транспортов
   (XHTTP/gRPC/WS — по наблюдениям сообщества эти транспорты меньше похожи
   на детектируемый VPN-туннель, см. пояснение ниже)
 - даёт дополнительный бонус всем TCP-based протоколам (vless/trojan) —
   на сотовых сетях РФ операторы чаще и сильнее душат/дросселируют UDP/QUIC
   (на чём построен Hysteria2), чем TCP:443+TLS (см. пояснение ниже)
 - учитывает подтверждения "работает" от небольшой доверенной группы людей,
   собранные collect_reports.py из Telegram (см. пояснение ниже)
 - НЕ резервирует фиксированное количество мест под какой-либо протокол —
   протоколы набираются естественно, по реальному рейтингу
 - не даёт одной стране занять больше MAX_PER_COUNTRY мест (это единственный
   фиксированный лимит распределения)
 - берёт не больше MAX_SERVERS
 - переименовывает remark в "Страна Город Флаг" (подтверждённые отзывом
   серверы дополнительно помечаются "✅")
 - кодирует итоговый список в base64 (стандартный формат подписки для Karing/Hiddyfi/v2rayNG)
 - пишет output/subscription.txt (то, на что будет указывать финальная ссылка подписки)
 - также пишет output/subscription_readable.txt (для проверки человеком, без base64)

Про исключение России:
 Цель подписки — обход блокировок Роскомнадзора внутри РФ. Сервер, который
 сам физически находится в России, не даёт этого сделать: трафик до него
 всё равно идёт через российскую сеть и попадает под те же DPI-блокировки,
 которые подписка должна обходить. Поэтому такие серверы отсеиваются на
 этом шаге целиком, независимо от пинга или протокола.

Про лимит на страну:
 GitHub-раннеры физически ближе к Канаде/США, поэтому пинг оттуда почти
 всегда ниже - без лимита подписка на 80%+ состоит из одной-двух стран.
 Это единственный фиксированный лимит распределения — количество серверов
 по протоколам сознательно не фиксируется (см. выше).

Про бонус за транспорт:
 Никакой конфиг не гарантированно проходит везде - это физическое
 ограничение, а не пробел в скрипте (см. обсуждение в чате). Но по общим
 наблюдениям сообщества (например, README проекта igareck/vpn-configs-for-russia)
 транспорты XHTTP, gRPC и WS в среднем стабильнее "голого" TLS. Этот бонус
 — небольшая (не решающая) добавка к сортировке, меньше бонуса Reality,
 которая слегка приподнимает такие конфиги при равном пинге.

Про бонус за сотовую сеть (CELLULAR_BONUS_MS):
 Это физическое ограничение сети, а не баг сервера или скрипта. Hysteria2
 работает через UDP/QUIC, и на сотовых сетях РФ это чаще всего душится
 сильнее, чем TCP:443+TLS. Бонус не убирает Hysteria2 из подписки — он
 просто поднимает vless/trojan выше при прочих равных, независимо от того,
 подписаны ли они как "только WiFi" в названии или нет.

Про подтверждения пользователей (REPORT_BONUS_MS):
 igareck/vpn-configs-for-russia тестирует серверы с сервера внутри России —
 у нас такого сервера нет, GitHub Actions runner физически сидит за
 пределами РФ и не видит блокировки РКН так, как их видит реальный
 пользователь. Поэтому вместо автотеста "изнутри" используется подтверждение
 небольшой доверенной группы людей (см. collect_reports.py): кто-то реально
 открыл сервер на своём телефоне/WiFi в России и написал боту его имя.
 Подтверждение актуально REPORT_TTL_HOURS часов — дальше считается
 устаревшим, потому что публичный сервер под тем же именем может со
 временем смениться.
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
REPORTS_FILE = os.path.join(OUT_DIR, "server_reports.json")

MAX_SERVERS = 200
REALITY_BONUS_MS = 50
TRANSPORT_BONUS_MS = 20  # для type=xhttp/grpc/ws — меньше REALITY_BONUS_MS, это вторичный фактор
CELLULAR_BONUS_MS = 80   # бонус TCP-based протоколам (vless/trojan) — устойчивее на сотовой,
                          # т.к. UDP/QUIC (Hysteria2) чаще душится операторами РФ на мобильной сети
STABLE_TRANSPORTS = {"xhttp", "grpc", "ws"}
MAX_PER_COUNTRY = 10      # единственный фиксированный лимит — не больше стольких серверов на страну
EXCLUDED_COUNTRIES = {"RU"}  # серверы внутри России не помогают обходить блокировки РКН

REPORT_BONUS_MS = 150    # больше REALITY_BONUS_MS — подтверждённый человеком сервер важнее
REPORT_TTL_HOURS = 48    # сколько часов подтверждение считается актуальным

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
    """True, если для этого имени сервера есть подтверждение "работает"
    не старше REPORT_TTL_HOURS часов."""
    entry = reports.get(display_name)
    if not entry or not entry.get("last_ok"):
        return False
    try:
        last_ok = datetime.fromisoformat(entry["last_ok"])
    except ValueError:
        return False
    return (now - last_ok) <= timedelta(hours=REPORT_TTL_HOURS)


def rename_uri(raw: str, display_name: str) -> str:
    base = raw.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(display_name)}"


def extract_transport(raw: str) -> str:
    """Достаёт значение параметра type= из самой ссылки, без парсинга всей URI."""
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


def select_with_quota(configs, sort_key):
    """Топ MAX_SERVERS по sort_key, с единственным лимитом MAX_PER_COUNTRY
    серверов на одну страну (country_code). Количество серверов по
    протоколам не резервируется и не фиксируется."""
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


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    reports = load_reports()
    now = datetime.now(timezone.utc)
    sort_key = make_sort_key(reports, now)

    configs = select_with_quota(configs, sort_key)

    final_lines = []
    for c in configs:
        display_name = c.get("display_name") or c.get("remark") or "VPN"
        original_name = display_name

        if is_confirmed(original_name, reports, now):
            display_name = f"{display_name} \u2705"

        final_lines.append(rename_uri(c["raw"], display_name))

    body = "\n".join(final_lines)

    with open(OUT_READABLE, "w", encoding="utf-8") as f:
        f.write(body + "\n")

    encoded = base64.b64encode(body.encode("utf-8")).decode("utf-8")
    with open(OUT_SUB, "w", encoding="utf-8") as f:
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
    print(f"В финальную подписку вошло {len(final_lines)} серверов (лимит {MAX_SERVERS}), "
          f"из них Reality: {reality_count}, Hysteria2: {hy2_count}, "
          f"стабильные транспорты (xhttp/grpc/ws): {stable_transport_count}, "
          f"подтверждено пользователями: {confirmed_count}, "
          f"стран: {countries_count} (лимит {MAX_PER_COUNTRY} на страну, "
          f"исключены: {', '.join(sorted(EXCLUDED_COUNTRIES)) or 'нет'}).")
    print(f"Файл подписки: {OUT_SUB}")


if __name__ == "__main__":
    main()
