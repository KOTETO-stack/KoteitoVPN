#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_watchdog.py

Сторож подписки. ТОЛЬКО ЧИТАЕТ файлы репозитория и пишет в Telegram,
в репозиторий ничего не меняет.

Что делает:
 1. Считает серверы: пул (output/raw_servers.txt), основная подписка,
    вторая подписка; смотрит возраст raw_servers.txt по истории git и
    (если есть) индикатор давления блокировок OONI.
 2. Сравнивает с порогами (константы ниже).
 3. Если есть проблемы, просит бесплатную модель GitHub Models коротко
    объяснить вероятную причину. Модель получает только цифры, которые
    посчитал сам скрипт; тексты из внешних списков ей не передаются.
 4. Отправляет сообщение в Telegram. При обычном запуске по расписанию
    сообщение приходит только при проблемах; при ручном запуске
    (ALWAYS_REPORT=true) отчёт приходит всегда.

Страховки: если модель недоступна (лимиты, нет доступа у организации и т.п.),
отчёт уходит без комментария ИИ. Любая ошибка не роняет workflow.
"""
import json
import os
import subprocess
import time
import urllib.parse
import urllib.request

ROOT = os.path.join(os.path.dirname(__file__), "..")
OUT = os.path.join(ROOT, "output")

MIN_POOL = 30              # серверов в output/raw_servers.txt
MIN_MAIN = 20              # серверов в основной подписке
MIN_SECOND = 5             # серверов во второй подписке
MAX_RAW_AGE_HOURS = 3      # raw_servers.txt не менялся дольше этого — сбор завис

AI_URL = "https://models.github.ai/inference/chat/completions"
AI_MODEL = os.environ.get("AI_MODEL", "openai/gpt-4o-mini")
AI_TIMEOUT = 60


def read_lines(path):
    """Непустые строки без комментариев (#)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except OSError:
        return []


def last_commit_age_hours(rel_path):
    try:
        res = subprocess.run(
            ["git", "log", "-1", "--format=%ct", "--", rel_path],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        out = res.stdout.strip()
        if not out:
            return None
        return (time.time() - int(out)) / 3600.0
    except Exception:
        return None


def load_ooni_pressure():
    try:
        with open(os.path.join(OUT, "ooni_censorship_index.json"), "r", encoding="utf-8") as f:
            return json.load(f).get("pressure_percent")
    except Exception:
        return None


def collect_stats():
    pool = read_lines(os.path.join(OUT, "raw_servers.txt"))
    main = read_lines(os.path.join(OUT, "subscription_readable.txt"))
    second = read_lines(os.path.join(OUT, "subscription_cellular_readable.txt"))
    return {
        "pool": len(pool),
        "main": len(main),
        "main_hy2": sum(1 for ln in main if ln.startswith(("hysteria2://", "hy2://"))),
        "main_reality": sum(1 for ln in main if "security=reality" in ln),
        "second": len(second),
        "raw_age_hours": last_commit_age_hours("output/raw_servers.txt"),
        "ooni_pressure": load_ooni_pressure(),
    }


def find_problems(s):
    problems = []
    if s["pool"] < MIN_POOL:
        problems.append("Пул серверов мал: %d (порог %d)" % (s["pool"], MIN_POOL))
    if s["main"] < MIN_MAIN:
        problems.append("Основная подписка мала: %d (порог %d)" % (s["main"], MIN_MAIN))
    if s["second"] < MIN_SECOND:
        problems.append("Вторая подписка мала: %d (порог %d)" % (s["second"], MIN_SECOND))
    age = s["raw_age_hours"]
    if age is None:
        problems.append("Не удалось определить, когда последний раз менялся raw_servers.txt")
    elif age > MAX_RAW_AGE_HOURS:
        problems.append("raw_servers.txt не обновлялся %.1f ч (порог %d ч)" % (age, MAX_RAW_AGE_HOURS))
    return problems


def ai_comment(stats, problems):
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return ""
    system = (
        "Ты помощник, который следит за автоматической сборкой VPN-подписки. "
        "Отвечай по-русски, не больше 4 коротких предложений: что похоже на причину "
        "и что проверить в первую очередь. Опирайся только на переданные цифры, "
        "не выдумывай данные. Ты ничего не меняешь, только советуешь."
    )
    user = (
        "Цифры: " + json.dumps(stats, ensure_ascii=False) + "\n"
        "Проблемы: " + "; ".join(problems) + "\n"
        "Контекст: сбор (collect_and_test) раз в час собирает серверы из публичных списков, "
        "проверяет их через sing-box и пишет raw_servers.txt; затем build_subscription "
        "собирает основную и вторую подписки."
    )
    payload = {
        "model": AI_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
        "max_tokens": 300,
    }
    try:
        req = urllib.request.Request(
            AI_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return (data["choices"][0]["message"]["content"] or "").strip()
    except Exception as e:
        print("ИИ недоступен (%s), отчёт уйдёт без комментария." % e)
        return ""


def send_telegram(text):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID не заданы, сообщение не отправлено:")
        print(text)
        return
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text[:4000]}).encode("utf-8")
    req = urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % token, data=data)
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


def build_message(stats, problems, comment):
    age = stats["raw_age_hours"]
    ooni = stats["ooni_pressure"]
    lines = [
        "⚠️ KoteitoVPN: есть проблемы" if problems else "✅ KoteitoVPN: всё в норме",
        "",
        "Пул (raw_servers): %d" % stats["pool"],
        "Основная подписка: %d (Hysteria2: %d, Reality: %d)"
        % (stats["main"], stats["main_hy2"], stats["main_reality"]),
        "Вторая подписка: %d" % stats["second"],
        "raw_servers.txt обновлён: %s" % ("%.1f ч назад" % age if age is not None else "неизвестно"),
        "Давление блокировок OONI: %s" % ("%s%%" % ooni if ooni is not None else "нет данных"),
    ]
    if problems:
        lines += ["", "Проблемы:"] + ["- " + p for p in problems]
    if comment:
        lines += ["", "Комментарий ИИ:", comment]
    return "\n".join(lines)


def main():
    stats = collect_stats()
    problems = find_problems(stats)
    always = os.environ.get("ALWAYS_REPORT", "").lower() == "true"

    if not problems and not always:
        print("Всё в норме, сообщение не отправляется: %s" % json.dumps(stats, ensure_ascii=False))
        return

    comment = ai_comment(stats, problems) if problems else ""
    send_telegram(build_message(stats, problems, comment))
    print("Отчёт отправлен.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Сторож: непредвиденная ошибка (%s)." % e)
