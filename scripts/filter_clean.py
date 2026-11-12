#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
filter_clean.py
Чистит raw_configs.json:
 - оставляет только vless / trojan / hysteria2 (hy2)
 - выкидывает WARP, Tor/onion, явный мусор и "сомнительные" ноды (bns и т.п.)
 - дедуплицирует по host:port (а не по всей строке — так убираем клонов с разным именем)
Результат: clean_configs.json — список dict{proto, host, port, raw, remark}

Версия 2:
 - адрес берётся после ПОСЛЕДНЕГО "@" (раньше после первого: у ссылок вида
   proto://логин@пароль@хост:порт в "хост" попадал кусок "пароль@хост", и такие сервера
   выбрасывались как мусор). "@" в параметрах после "?" больше не мешает;
 - короткие слова-стоп (tor, test, bns, demo, fake, sample) ищутся как отдельные слова,
   а не как кусок слова: раньше "tor" убирал Toronto, Victoria, Doctor..., а "test" — fastest;
 - IP 1.1.1.1 ищется как целый адрес, раньше это был кусок любого адреса вида x1.1.1.1x;
 - в лог выводится, сколько адресов исправлено и сколько убрано по слову-стопу.

Версия 3:
 - адреса из BAD_HOSTS (github.com и т.п.) не могут быть VPN-сервером: такие записи
   (мусор в источниках) убираются.
"""
import json
import os
import re
import urllib.parse

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "raw_configs.json")
OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "clean_configs.json")

# слова-стоп, которые безопасно искать как кусок текста
BAD_SUBSTRINGS = [
    "warp", "wireguard", "onion", "expired", "invalid", "cloudflare-warp",
    "истек", "не работает",
]
# короткие слова-стоп: ищем только как отдельное слово (чтобы не убирать Toronto, fastest и т.п.)
BAD_WORDS = ["tor", "test", "bns", "demo", "fake", "sample"]

# адреса, которые не могут быть VPN-сервером (мусорные записи в источниках)
BAD_HOSTS = ("github.com", "githubusercontent.com")

_WORD_RE = re.compile(r"(?<![a-z0-9])(?:%s)(?![a-z0-9])" % "|".join(map(re.escape, BAD_WORDS)))
_IP_RE = re.compile(r"(?<![\d.])1\.1\.1\.1(?!\d)")

ALLOWED_PROTO = {"vless", "trojan", "hysteria2", "hy2"}

STATS = {"fixed_at": 0, "bad": 0}


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

        # сначала отделяем параметры: "@" внутри них не должен влиять на поиск адреса
        query_part = ""
        if "?" in rest:
            rest, query_part = rest.split("?", 1)

        hostport_part = rest
        if "@" in rest:
            if rest.count("@") > 1:
                STATS["fixed_at"] += 1
            hostport_part = rest.rsplit("@", 1)[1]
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
    host = entry["host"].lower().strip(".")
    if any(host == h or host.endswith("." + h) for h in BAD_HOSTS):
        return True
    haystack = f"{entry['remark']} {entry['host']}".lower()
    if any(s in haystack for s in BAD_SUBSTRINGS):
        return True
    return bool(_WORD_RE.search(haystack) or _IP_RE.search(haystack))


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        raw_list = json.load(f)

    parsed = []
    for raw in raw_list:
        entry = parse_config(raw)
        if entry is None:
            continue
        if is_bad(entry):
            STATS["bad"] += 1
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
    print(f"Исправлено адресов с несколькими «@»: {STATS['fixed_at']}; убрано по слову-стопу: {STATS['bad']}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
