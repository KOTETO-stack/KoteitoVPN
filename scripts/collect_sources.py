#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_sources.py
Скачивает конфиги (vless://, trojan://, hysteria2://, hy2://) из sources.txt.
Каждая ссылка может быть либо обычным текстом, либо base64-строкой — обрабатываем оба варианта.
Результат: raw_configs.json — список строк-конфигов (ещё не отфильтрованных).
"""
import base64
import json
import os
import re
import sys
import concurrent.futures as cf
import urllib.request

SOURCES_FILE = os.path.join(os.path.dirname(__file__), "..", "sources.txt")
OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "raw_configs.json")

PROTO_RE = re.compile(r"(?:vless|trojan|hysteria2|hy2)://[^\s\"'<>]+", re.IGNORECASE)
TIMEOUT = 12
UA = "Mozilla/5.0 (KoteitoVPN-collector)"


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

    print(f"[ok]   {url} -> {len(configs)} configs")
    return configs


def main():
    urls = load_sources()
    print(f"Источников в списке: {len(urls)}")
    all_configs = []
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        for result in ex.map(fetch_one, urls):
            all_configs.extend(result)

    unique = sorted(set(all_configs))
    print(f"Всего собрано: {len(all_configs)}, уникальных: {len(unique)}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique, f, ensure_ascii=False, indent=0)


if __name__ == "__main__":
    main()
