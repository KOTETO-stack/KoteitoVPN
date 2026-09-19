#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_ad_block_rules.py

ЧЕСТНО: заблокировать рекламу внутри самой строки vless://trojan://hysteria2://
невозможно — там просто нет такого поля, это адрес сервера, а не DNS-правила.
Реклама блокируется на уровне DNS/routing самого клиента (Karing).

Что реально можно сделать в пайплайне: скачивать актуальный список
рекламных доменов (AdGuard Base Filter) и хостить его в СВОЁМ репозитории
как output/ad_block_rules.txt. Тогда в Karing один раз добавляешь ссылку на
НАШ файл (а не на сторонний), и дальше он сам обновляется каждый час вместе
с остальной подпиской - без ручных действий.
"""
import os
import urllib.request

SOURCE_URL = "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
OUT_FILE = os.path.join(OUT_DIR, "ad_block_rules.txt")
TIMEOUT = 15


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    try:
        req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "KoteitoVPN-adblock"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[adblock] не удалось скачать список: {e}")
        return

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(data)

    lines = [l for l in data.splitlines() if l.strip() and not l.strip().startswith("!")]
    print(f"[adblock] сохранено правил: {len(lines)}")


if __name__ == "__main__":
    main()
