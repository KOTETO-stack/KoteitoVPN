#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_subscription.py
Финальный шаг workflow №2:
 - сортирует по пингу с бонусами для Reality и для "стабильных" транспортов
   (XHTTP/gRPC/WS — по наблюдениям сообщества эти транспорты меньше похожи
   на детектируемый VPN-туннель, см. пояснение ниже)
 - даёт дополнительный бонус всем TCP-based протоколам (vless/trojan) —
   на сотовых сетях РФ операторы чаще и сильнее душат/дросселируют UDP/QUIC
   (на чём построен Hysteria2), чем TCP:443+TLS (см. пояснение ниже)
 - резервирует минимум HY2_MIN_SERVERS мест для Hysteria2 (см. пояснение)
 - не даёт одной стране занять больше MAX_PER_COUNTRY мест
 - берёт не больше MAX_SERVERS
 - переименовывает remark в "Страна Город Флаг" (Hysteria2 дополнительно
   помечается "⚠️WiFi", т.к. на сотовой сети менее надёжен)
 - кодирует итоговый список в base64 (стандартный формат подписки для Karing/Hiddyfi/v2rayNG)
 - пишет output/subscription.txt (то, на что будет указывать финальная ссылка подписки)
 - также пишет output/subscription_readable.txt (для проверки человеком, без base64)

Про резерв для Hysteria2:
 ping_test.py на этапе 1 делает для Hysteria2 не настоящий пинг, а UDP-проб
 порта - если сервер не отвечает мгновенно (частый случай для QUIC), в
 ping_ms подставляется значение около 499 мс (почти MAX_PING_MS). Из-за этого
 при простой сортировке по ping_ms все Hysteria2-сервера проваливаются в
 конец списка. Резерв не даёт протоколу целиком вымыться из подписки.

Про лимит на страну:
 GitHub-раннеры физически ближе к Канаде/США, поэтому пинг оттуда почти
 всегда ниже - без лимита подписка на 80%+ состоит из одной-двух стран.

Про бонус за транспорт:
 Никакой конфиг не гарантированно проходит везде - это физическое
 ограничение, а не пробел в скрипте (см. обсуждение в чате). Но по общим
 наблюдениям сообщества (например, README проекта igareck/vpn-configs-for-russia)
 транспорты XHTTP, gRPC и WS в среднем стабильнее "голого" TLS. Этот бонус
 — небольшая (не решающая) добавка к сортировке, меньше бонуса Reality,
 которая слегка приподнимает такие конфиги при равном пинге.

Про бонус за сотовую сеть (CELLULAR_BONUS_MS):
 Это тоже физическое ограничение сети, а не баг сервера или скрипта.
 Hysteria2 работает через UDP/QUIC, и на сотовых сетях РФ это чаще всего
 душится сильнее, чем TCP:443+TLS. Бонус не убирает Hysteria2 из подписки
 (резерв HY2_MIN_SERVERS сохранён без изменений) — он просто поднимает
 vless/trojan выше при прочих равных, чтобы верхние позиции списка были
 надёжнее именно на мобильном интернете.
"""
import base64
import json
import os
import re
import urllib.parse

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "masked_configs.json")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
OUT_SUB = os.path.join(OUT_DIR, "subscription.txt")
OUT_READABLE = os.path.join(OUT_DIR, "subscription_readable.txt")

MAX_SERVERS = 200
REALITY_BONUS_MS = 50
TRANSPORT_BONUS_MS = 20  # для type=xhttp/grpc/ws — меньше REALITY_BONUS_MS, это вторичный фактор
CELLULAR_BONUS_MS = 80   # бонус TCP-based протоколам (vless/trojan) — устойчивее на сотовой,
                          # т.к. UDP/QUIC (Hysteria2) чаще душится операторами РФ на мобильной сети
STABLE_TRANSPORTS = {"xhttp", "grpc", "ws"}
HY2_MIN_SERVERS = 30    # минимум мест для Hysteria2 в подписке — не уменьшено, протокол
                          # остаётся полностью представлен (для WiFi/домашних сетей)
MAX_PER_COUNTRY = 10    # не больше стольких серверов на одну страну

TYPE_RE = re.compile(r"[?&]type=([a-zA-Z0-9_-]+)", re.IGNORECASE)


def rename_uri(raw: str, display_name: str) -> str:
    base = raw.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(display_name)}"


def extract_transport(raw: str) -> str:
    """Достаёт значение параметра type= из самой ссылки, без парсинга всей URI."""
    m = TYPE_RE.search(raw)
    return m.group(1).lower() if m else ""


def sort_key(c):
    ping = c.get("ping_ms", 9999)
    bonus = REALITY_BONUS_MS if c.get("security_tag") == "reality" else 0
    if extract_transport(c.get("raw", "")) in STABLE_TRANSPORTS:
        bonus += TRANSPORT_BONUS_MS
    if c.get("proto") != "hysteria2":
        bonus += CELLULAR_BONUS_MS
    return ping - bonus


def select_with_quota(configs):
    """Топ MAX_SERVERS по sort_key, с резервом мест под Hysteria2 и лимитом
    MAX_PER_COUNTRY серверов на одну страну (country_code)."""
    configs = sorted(configs, key=sort_key)

    country_count = {}
    hy2_count = 0
    selected = []
    selected_ids = set()

    # Проход 1: резервируем лучшие Hysteria2, тоже уважая лимит на страну.
    for c in configs:
        if len(selected) >= MAX_SERVERS or hy2_count >= HY2_MIN_SERVERS:
            break
        if c.get("proto") != "hysteria2":
            continue
        cc = c.get("country_code", "??")
        if country_count.get(cc, 0) >= MAX_PER_COUNTRY:
            continue
        selected.append(c)
        selected_ids.add(id(c))
        country_count[cc] = country_count.get(cc, 0) + 1
        hy2_count += 1

    # Проход 2: заполняем остальные места лучшими по sort_key, уважая тот же лимит.
    for c in configs:
        if len(selected) >= MAX_SERVERS:
            break
        if id(c) in selected_ids:
            continue
        cc = c.get("country_code", "??")
        if country_count.get(cc, 0) >= MAX_PER_COUNTRY:
            continue
        selected.append(c)
        selected_ids.add(id(c))
        country_count[cc] = country_count.get(cc, 0) + 1

    selected.sort(key=sort_key)
    return selected


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    configs = select_with_quota(configs)

    final_lines = []
    for c in configs:
        display_name = c.get("display_name") or c.get("remark") or "VPN"
        if c.get("proto") == "hysteria2":
            display_name = f"{display_name} ⚠️WiFi"
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
    countries_count = len({c.get("country_code", "??") for c in configs})
    print(f"В финальную подписку вошло {len(final_lines)} серверов (лимит {MAX_SERVERS}), "
          f"из них Reality: {reality_count}, Hysteria2: {hy2_count}, "
          f"стабильные транспорты (xhttp/grpc/ws): {stable_transport_count}, "
          f"стран: {countries_count} (лимит {MAX_PER_COUNTRY} на страну).")
    print(f"Файл подписки: {OUT_SUB}")


if __name__ == "__main__":
    main()
