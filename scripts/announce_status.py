#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
announce_status.py
Раз в час отправляет в Telegram короткую сводку: сколько серверов сейчас в
подписке, разбивка по протоколам и странам, когда последний раз обновлялась.
Если секреты TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID не заданы — тихо завершается
без ошибки (это не критичный шаг, просто удобство).
"""
import collections
import os
import urllib.parse
import urllib.request

ROOT = os.path.join(os.path.dirname(__file__), "..")
SUB_READABLE = os.path.join(ROOT, "output", "subscription_readable.txt")

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


def send_telegram(text):
    if not BOT_TOKEN or not CHAT_ID:
        print("TELEGRAM_BOT_TOKEN/CHAT_ID не заданы — пропускаем уведомление.")
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": CHAT_ID, "text": text}).encode()
    try:
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
        print("Отправлено в Telegram.")
    except Exception as e:
        print(f"Не удалось отправить в Telegram: {e}")


def main():
    if not os.path.exists(SUB_READABLE):
        send_telegram("⚠️ KoteitoVPN: output/subscription_readable.txt пока не существует — подписка ещё не собиралась.")
        return

    with open(SUB_READABLE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    proto_counts = collections.Counter()
    country_counts = collections.Counter()
    for line in lines:
        proto = line.split("://", 1)[0].lower()
        proto_counts[proto] += 1
        if "#" in line:
            remark = urllib.parse.unquote(line.split("#", 1)[1])
            country = remark.split(" ")[0] if remark else "?"
            country_counts[country] += 1

    total = len(lines)
    proto_line = ", ".join(f"{p}: {c}" for p, c in proto_counts.most_common())
    top_countries = ", ".join(f"{c}({n})" for c, n in country_counts.most_common(5))

    text = (
        f"📊 KoteitoVPN — статус подписки\n"
        f"Всего серверов: {total}\n"
        f"По протоколам: {proto_line or 'нет данных'}\n"
        f"Топ стран: {top_countries or 'нет данных'}"
    )
    send_telegram(text)


if __name__ == "__main__":
    main()
