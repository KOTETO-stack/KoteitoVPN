#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_reports.py
Собирает подтверждения "этот сервер работает" от небольшой доверенной
группы людей через того же Telegram-бота, что уже используется в
announce_status.py.

Как это работает:
 - Бот НЕ добавляется в общий чат — каждый из доверенных людей просто пишет
   боту напрямую в личку СООБЩЕНИЕ, РАВНОЕ ИМЕНИ СЕРВЕРА, которое видно в
   приложении (Karing/Hiddyfi), например:
     Канада Торонто 🇨🇦 -3
   Никакого "+"/"-" не нужно — просто имя = "этот сервер у меня открылся".
   Про сервера, которые НЕ открылись, писать не нужно вообще (их и так
   отсекает ping_test.py и естественная сортировка по пингу).
 - Скрипт через Telegram Bot API getUpdates забирает новые сообщения,
   проверяет, что автор входит в список доверенных ALLOWED_REPORTER_IDS
   (иначе сообщение игнорируется — защита от посторонних отзывов),
   и копит подтверждения в output/server_reports.json.
 - build_subscription.py потом читает этот файл и слегка поднимает в
   сортировке серверы с недавним подтверждением, помечая их "✅".
 - Смещение (offset) последнего обработанного сообщения Telegram хранится
   в output/telegram_offset.json, чтобы не обрабатывать одни и те же
   сообщения повторно при следующем запуске.

Важная оговорка: имена серверов не гарантированно стабильны между
пересборками (источники конфигов публичные, сервер под тем же именем
может со временем заменяться другим) — поэтому у подтверждения есть срок
жизни (REPORT_TTL_HOURS в build_subscription.py), после которого оно
перестаёт учитываться.

Нужные секреты в GitHub Actions (Settings → Secrets and variables → Actions):
 - TELEGRAM_BOT_TOKEN     (уже есть, используется и в announce_status.py)
 - ALLOWED_REPORTER_IDS   (числовые Telegram user_id через запятую,
                           например: "123456789,987654321")

Как узнать свой Telegram user_id (и id ваших пары доверенных людей):
 1. Каждый из них должен написать что угодно боту в личку.
 2. Открыть в браузере (замените <TOKEN> на реальный токен бота):
    https://api.telegram.org/bot<TOKEN>/getUpdates
 3. В ответе (JSON) найти "from":{"id": ЧИСЛО, ...} — это и есть user_id.
"""
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
REPORTS_FILE = os.path.join(OUT_DIR, "server_reports.json")
OFFSET_FILE = os.path.join(OUT_DIR, "telegram_offset.json")

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
ALLOWED_IDS = {
    x.strip()
    for x in os.environ.get("ALLOWED_REPORTER_IDS", "").split(",")
    if x.strip()
}


def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_updates(offset):
    if not BOT_TOKEN:
        print("TELEGRAM_BOT_TOKEN не задан — пропускаю сбор подтверждений.")
        return []
    url = (
        f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
        f"?offset={offset}&timeout=0&allowed_updates=%5B%22message%22%5D"
    )
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"Не удалось получить обновления от Telegram: {e}")
        return []
    if not data.get("ok"):
        print(f"Telegram API вернул ошибку: {data}")
        return []
    return data.get("result", [])


def main():
    if not ALLOWED_IDS:
        print("ALLOWED_REPORTER_IDS не задан — подтверждения никого не принимаются "
              "(это нормально до первой настройки).")

    offset_state = load_json(OFFSET_FILE, {"last_update_id": 0})
    reports = load_json(REPORTS_FILE, {})

    updates = get_updates(offset_state.get("last_update_id", 0) + 1)
    max_update_id = offset_state.get("last_update_id", 0)
    accepted = 0
    ignored = 0

    now_iso = datetime.now(timezone.utc).isoformat()

    for update in updates:
        update_id = update.get("update_id", 0)
        max_update_id = max(max_update_id, update_id)

        msg = update.get("message")
        if not msg:
            continue

        sender_id = str(msg.get("from", {}).get("id", ""))
        text = (msg.get("text") or "").strip()

        if sender_id not in ALLOWED_IDS or not text:
            ignored += 1
            continue

        # Текст сообщения = точное имя сервера, которое сейчас работает.
        server_name = text
        entry = reports.setdefault(server_name, {"ok_count": 0, "last_ok": None})
        entry["ok_count"] += 1
        entry["last_ok"] = now_iso
        accepted += 1

    save_json(REPORTS_FILE, reports)
    save_json(OFFSET_FILE, {"last_update_id": max_update_id})

    print(f"Обработано сообщений: {len(updates)}, принято подтверждений: {accepted}, "
          f"игнорировано (не из списка доверенных / пустой текст): {ignored}.")
    print(f"Файл подтверждений: {REPORTS_FILE}")


if __name__ == "__main__":
    main()
