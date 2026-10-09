#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_sources.py
Скачивает конфиги (vless://, trojan://, hysteria2://, hy2://) из sources.txt.
Каждая ссылка может быть либо обычным текстом, либо base64-строкой — обрабатываем оба варианта.
Результат: raw_configs.json — список строк-конфигов (ещё не отфильтрованных).

Про дедупликацию по host:port:
 Уникальность проверяется по (host, port), извлечённым из самой ссылки, а не
 по строке целиком — так разные источники, отдающие один и тот же физический
 сервер под чуть разным форматом ссылки, не дают "ложных" дублей в списке.

Про MAX_PER_SOURCE и MAX_TOTAL_CANDIDATES:
 Некоторые источники (например, списки с десятками тысяч строк) могут одним
 списком "забить" весь объём, так что ping_test.py/dns_test.py не успевают
 проверить всё за отведённое время workflow, и запуск отменяется по таймауту.
 Чтобы ни один источник не монополизировал пул, сверх MAX_PER_SOURCE конфигов
 из одного источника берётся случайная выборка этого размера (а не все) —
 источник остаётся в деле, просто не перекрывает всех остальных. Сверху же
 стоит общий предохранитель MAX_TOTAL_CANDIDATES: если после дедупликации
 кандидатов всё равно больше этого числа, берётся случайная выборка из них.
 Оба ограничения — защита по объёму, а не попытка угадать "какие конфиги
 лучше"; реальная проверка качества (жив ли сервер) происходит дальше, в
 ping_test.py/dns_test.py.
"""
import base64
import json
import os
import random
import re
import sys
import concurrent.futures as cf
import urllib.request

SOURCES_FILE = os.path.join(os.path.dirname(__file__), "..", "sources.txt")
OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "raw_configs.json")

PROTO_RE = re.compile(r"(?:vless|trojan|hysteria2|hy2)://[^\s\"'<>]+", re.IGNORECASE)
HOST_PORT_RE = re.compile(r"://[^@/]*@([^:/?#\s]+):(\d{1,5})", re.IGNORECASE)
TIMEOUT = 12
UA = "Mozilla/5.0 (KoteitoVPN-collector)"

MAX_PER_SOURCE = 1500
MAX_TOTAL_CANDIDATES = 12000


def load_sources():
    urls = []
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def try_base64_decode(text):
    """Если содержимое — это одна base64-строка (частый формат подписок), декодируем."""
    stripped = text.strip().replace("\n", "").replace("\r", "")
    if len(stripped) < 20:
        return None
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", stripped):
        for pad in range(0, 4):
            try:
                candidate = stripped + ("=" * pad)
                decoded = base64.b64decode(candidate, validate=False).decode("utf-8", errors="ignore")
                if "://" in decoded:
                    return decoded
            except Exception:
                continue
    return None


def host_port_key(raw):
    """Извлекает (host, port) из ссылки для дедупликации. Если не удалось
    распарсить — возвращает саму строку целиком, чтобы такая запись не
    склеилась ни с чем по ошибке."""
    m = HOST_PORT_RE.search(raw)
    if m:
        return (m.group(1).lower(), m.group(2))
    return (raw,)


def fetch_one(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[skip] {url} -> {e}", file=sys.stderr)
        return []

    configs = PROTO_RE.findall(raw)

    decoded = try_base64_decode(raw)
    if decoded:
        configs += PROTO_RE.findall(decoded)

    if not configs:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            dec = try_base64_decode(line)
            if dec:
                configs += PROTO_RE.findall(dec)

    total_found = len(configs)
    if total_found > MAX_PER_SOURCE:
        configs = random.sample(configs, MAX_PER_SOURCE)
        print(f"[ok]   {url} -> {total_found} configs (взято случайных {MAX_PER_SOURCE})")
    else:
        print(f"[ok]   {url} -> {total_found} configs")
    return configs


def main():
    urls = load_sources()
    print(f"Источников в списке: {len(urls)}")
    all_configs = []
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        for result in ex.map(fetch_one, urls):
            all_configs.extend(result)

    seen = {}
    for raw in all_configs:
        key = host_port_key(raw)
        if key not in seen:
            seen[key] = raw
    unique = list(seen.values())

    print(f"Всего собрано: {len(all_configs)}, уникальных по host:port: {len(unique)}")

    if len(unique) > MAX_TOTAL_CANDIDATES:
        unique = random.sample(unique, MAX_TOTAL_CANDIDATES)
        print(f"Превышен общий предохранитель — взята случайная выборка {MAX_TOTAL_CANDIDATES} из {len(seen)}")

    unique = sorted(unique)

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique, f, ensure_ascii=False, indent=0)


if __name__ == "__main__":
    main()
