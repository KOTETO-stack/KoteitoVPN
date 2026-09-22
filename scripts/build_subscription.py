#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_subscription.py
Финальный шаг workflow №2:
 - сортирует по пингу с бонусом для Reality (устойчивее к DPI - при близком
   пинге приоритет ему, а не просто "кто на 5мс быстрее")
 - резервирует минимум HY2_MIN_SERVERS мест для Hysteria2 (см. ниже, почему)
 - берёт не больше MAX_SERVERS
 - переименовывает remark в "Страна Город Флаг"
 - кодирует итоговый список в base64 (стандартный формат подписки для Karing/Hiddyfi/v2rayNG)
 - пишет output/subscription.txt (то, на что будет указывать финальная ссылка подписки)
 - также пишет output/subscription_readable.txt (для проверки человеком, без base64)

Про резерв для Hysteria2:
 ping_test.py на этапе 1 делает для Hysteria2 не настоящий пинг, а UDP-проб
 порта - если сервер не отвечает мгновенно (частый случай для QUIC), в
 ping_ms подставляется значение около 499 мс (почти MAX_PING_MS). Из-за этого
 при простой сортировке по ping_ms все Hysteria2-сервера проваливаются в
 конец списка и не попадают в топ MAX_SERVERS, даже если они реально прошли
 тест через sing-box на этапе 2 (real_ms). Резерв не даёт протоколу целиком
 вымыться из подписки из-за особенностей этой метрики.
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
REALITY_BONUS_MS = 50
HY2_MIN_SERVERS = 30  # минимум мест для Hysteria2 в топ-150, см. пояснение выше


def rename_uri(raw: str, display_name: str) -> str:
    base = raw.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(display_name)}"


def sort_key(c):
    ping = c.get("ping_ms", 9999)
    bonus = REALITY_BONUS_MS if c.get("security_tag") == "reality" else 0
    return ping - bonus


def select_with_quota(configs):
    """Топ MAX_SERVERS по sort_key, но не меньше HY2_MIN_SERVERS лучших Hysteria2,
    если их вообще столько набралось."""
    configs = sorted(configs, key=sort_key)

    hy2 = [c for c in configs if c.get("proto") == "hysteria2"]
    reserved = hy2[:HY2_MIN_SERVERS]
    reserved_ids = {id(c) for c in reserved}

    rest = [c for c in configs if id(c) not in reserved_ids]
    remaining_slots = max(0, MAX_SERVERS - len(reserved))

    selected = reserved + rest[:remaining_slots]
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
        final_lines.append(rename_uri(c["raw"], display_name))

    body = "\n".join(final_lines)

    with open(OUT_READABLE, "w", encoding="utf-8") as f:
        f.write(body + "\n")

    encoded = base64.b64encode(body.encode("utf-8")).decode("utf-8")
    with open(OUT_SUB, "w", encoding="utf-8") as f:
        f.write(encoded)

    reality_count = sum(1 for c in configs if c.get("security_tag") == "reality")
    hy2_count = sum(1 for c in configs if c.get("proto") == "hysteria2")
    print(f"В финальную подписку вошло {len(final_lines)} серверов (лимит {MAX_SERVERS}), "
          f"из них Reality: {reality_count}, Hysteria2: {hy2_count}.")
    print(f"Файл подписки: {OUT_SUB}")


if __name__ == "__main__":
    main()
