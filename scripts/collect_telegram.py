#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_telegram.py

Собирает vless/trojan/hysteria2 конфиги из ПУБЛИЧНЫХ Telegram-каналов через их
открытую веб-страницу https://t.me/s/<канал>. Без входа в аккаунт, без API-ключей,
без Telegram-клиента: это те же страницы, которые видит любой посетитель.

Каналы берутся из telegram_channels.txt (по одному в строке; можно писать
name, @name, https://t.me/name или https://t.me/s/name; строки с # игнорируются).
Результат пишется в output/telegram_configs.txt (по одной ссылке в строке).
Дальше этот файл подхватывает обычный сборщик как один из источников: его raw-ссылка
добавляется в sources.txt.

Что делает скрипт с текстом из Telegram: только ищет в нём ссылки vless://, trojan://,
hysteria2://, hy2:// по шаблону. Ничего не выполняется и не открывается.

Страховки:
 - канал без публичной страницы или с ошибкой просто пропускается (пишется в лог);
 - между запросами пауза, общий бюджет времени TIME_BUDGET_SEC;
 - если ничего не найдено, старый output/telegram_configs.txt не затирается;
 - любая непредвиденная ошибка не роняет workflow (код выхода всегда 0).
"""
import html
import os
import re
import time
import urllib.error
import urllib.request

ROOT = os.path.join(os.path.dirname(__file__), "..")
CHANNELS_FILE = os.path.join(ROOT, "telegram_channels.txt")
OUT_FILE = os.path.join(ROOT, "output", "telegram_configs.txt")

PAGES_PER_CHANNEL = 5      # на странице ~20 сообщений; глубже = старее и мертвее
REQUEST_DELAY = 1.0        # пауза между запросами, сек
TIMEOUT = 20
TIME_BUDGET_SEC = 420
MAX_LINES = 20000
USER_AGENT = "Mozilla/5.0 (compatible; KoteitoVPN-collector/1.0)"

URI_RE = re.compile(r"(?:vless|trojan|hysteria2|hy2)://[^\s<>\"'`]+", re.IGNORECASE)
VALID_RE = re.compile(
    r"^(?:vless|trojan|hysteria2|hy2)://[^@\s]+@(?:\[[0-9a-fA-F:]+\]|[^:/?#\s]+):\d{1,5}",
    re.IGNORECASE,
)
POST_ID_RE = re.compile(r'data-post="[^"/]+/(\d+)"')
TRAILING = ".,;:!?)]}>»“”‘’"


def normalize_channel(line):
    s = line.strip()
    if not s or s.startswith("#"):
        return ""
    s = re.sub(r"^https?://t\.me/(s/)?", "", s, flags=re.IGNORECASE)
    s = s.lstrip("@").split("?", 1)[0].strip("/ ")
    return s if re.fullmatch(r"[A-Za-z0-9_]{3,64}", s) else ""


def load_channels():
    try:
        with open(CHANNELS_FILE, "r", encoding="utf-8") as f:
            names = [normalize_channel(ln) for ln in f]
    except OSError:
        return []
    seen, result = set(), []
    for n in names:
        if n and n.lower() not in seen:
            seen.add(n.lower())
            result.append(n)
    return result


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Language": "en"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def page_text(page):
    """HTML -> простой текст: переносы на границах блоков, теги убраны, сущности раскрыты."""
    page = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", page)
    page = re.sub(r"(?i)<br\s*/?>|</(div|p|code|pre|li)>", "\n", page)
    page = re.sub(r"<[^>]+>", "", page)
    return html.unescape(page)


def extract_configs(text):
    configs = []
    for m in URI_RE.finditer(text):
        uri = m.group(0).rstrip(TRAILING)
        if VALID_RE.match(uri):
            configs.append(uri)
    return configs


def parse_page(page):
    """(список конфигов, список id сообщений на странице)."""
    ids = [int(x) for x in POST_ID_RE.findall(page)]
    return extract_configs(page_text(page)), ids


def collect_channel(name, deadline):
    """Возвращает (конфиги, число страниц). Старые сообщения идут через ?before=<id>."""
    found, before, pages = [], None, 0
    for _ in range(PAGES_PER_CHANNEL):
        if time.time() > deadline:
            break
        url = "https://t.me/s/" + name + ("?before=%d" % before if before else "")
        page = fetch(url)
        pages += 1
        configs, ids = parse_page(page)
        found += configs
        if not ids:
            break
        before = min(ids)
        if before <= 1:
            break
        time.sleep(REQUEST_DELAY)
    return found, pages


def main():
    channels = load_channels()
    if not channels:
        print("telegram_channels.txt пуст или не найден — ничего не собираю.")
        return

    print("Каналов в списке: %d" % len(channels))
    deadline = time.time() + TIME_BUDGET_SEC
    unique = {}   # ключ: ссылка без #имени, чтобы один сервер не повторялся

    for name in channels:
        if time.time() > deadline:
            print("⏱ Бюджет времени исчерпан, остальные каналы пропущены.")
            break
        try:
            configs, pages = collect_channel(name, deadline)
        except (urllib.error.URLError, OSError, ValueError) as e:
            print("[skip] @%s -> %s" % (name, e))
            continue
        if pages and not configs:
            print("[ok]   @%s -> 0 configs (страниц: %d)" % (name, pages))
        else:
            print("[ok]   @%s -> %d configs (страниц: %d)" % (name, len(configs), pages))
        for uri in configs:
            unique.setdefault(uri.split("#", 1)[0], uri)
        time.sleep(REQUEST_DELAY)

    lines = list(unique.values())[:MAX_LINES]
    print("Всего собрано уникальных конфигов: %d" % len(lines))
    if not lines:
        print("Ничего не найдено, старый файл не перезаписываю.")
        return

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("Записано в %s" % OUT_FILE)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("collect_telegram: непредвиденная ошибка (%s)." % e)
