#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
promote_candidates.py
Механизм самостоятельного пополнения sources.txt:
 - читает candidate_sources.txt
 - для каждой ссылки пробует скачать и вытащить конфиги (тот же regex/base64
   разбор, что и в collect_sources.py — никакой новой логики исполнения кода,
   только чтение текста)
 - если ссылка отдала >= MIN_CONFIGS_TO_PROMOTE валидных конфигов —
   переносит её в sources.txt и убирает из candidate_sources.txt
 - если нет — оставляет в кандидатах на следующую попытку (источник может
   быть временно недоступен)

Запускается отдельным workflow "Expand Sources" раз в сутки. Не трогает
существующие sources.txt строки — только дописывает новые.
"""
import base64
import os
import re
import sys
import urllib.request

ROOT = os.path.join(os.path.dirname(__file__), "..")
SOURCES_FILE = os.path.join(ROOT, "sources.txt")
CANDIDATES_FILE = os.path.join(ROOT, "candidate_sources.txt")

PROTO_RE = re.compile(r"(?:vless|trojan|hysteria2|hy2)://[^\s\"'<>]+", re.IGNORECASE)
TIMEOUT = 12
UA = "Mozilla/5.0 (KoteitoVPN-candidate-check)"
MIN_CONFIGS_TO_PROMOTE = 3


def try_base64_decode(text):
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


def count_configs(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[dead] {url} -> {e}", file=sys.stderr)
        return 0

    configs = PROTO_RE.findall(raw)
    decoded = try_base64_decode(raw)
    if decoded:
        configs += PROTO_RE.findall(decoded)
    if not configs:
        for line in raw.splitlines():
            dec = try_base64_decode(line.strip())
            if dec:
                configs += PROTO_RE.findall(dec)
    return len(set(configs))


def load_lines(path):
    header, urls = [], []
    if not os.path.exists(path):
        return header, urls
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.rstrip("\n")
            if s.strip().startswith("#") or not s.strip():
                header.append(s)
            else:
                urls.append(s.strip())
    return header, urls


def main():
    cand_header, candidates = load_lines(CANDIDATES_FILE)
    src_header, sources = load_lines(SOURCES_FILE)

    promoted, still_candidates = [], []

    for url in candidates:
        if url in sources:
            print(f"[skip] {url} -> уже есть в sources.txt")
            continue
        n = count_configs(url)
        if n >= MIN_CONFIGS_TO_PROMOTE:
            print(f"[promote] {url} -> {n} конфигов, переносим в sources.txt")
            promoted.append(url)
        else:
            print(f"[keep-candidate] {url} -> только {n} конфигов, пробуем ещё раз завтра")
            still_candidates.append(url)

    if promoted:
        sources = sorted(set(sources + promoted))
        with open(SOURCES_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(src_header) + "\n\n")
            f.write("\n".join(sources) + "\n")

    with open(CANDIDATES_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(cand_header) + "\n\n" if cand_header else "")
        f.write("\n".join(still_candidates) + ("\n" if still_candidates else ""))

    print(f"Продвинуто в sources.txt: {len(promoted)}. Осталось кандидатов: {len(still_candidates)}.")


if __name__ == "__main__":
    main()
