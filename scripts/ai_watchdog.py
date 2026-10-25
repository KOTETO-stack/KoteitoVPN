#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_watchdog.py

Сторож подписки. ТОЛЬКО ЧИТАЕТ файлы репозитория и пишет в Telegram,
в репозиторий ничего не меняет.

Что делает:
 1. Считает серверы: пул (output/raw_servers.txt), основная подписка,
    вторая подписка; узнаёт, когда последний раз успешно отработал сбор
    (через GitHub API; если API недоступен, по истории git для raw_servers.txt);
    читает индикатор давления блокировок OONI.
 2. Сравнивает с порогами (константы ниже).
 3. Если есть проблемы, просит бесплатную модель GitHub Models коротко
    объяснить вероятную причину. Модель получает только цифры, которые
    посчитал сам скрипт. Если модель недоступна, причина попадает в отчёт.
 4. Отправляет сообщение в Telegram. При обычном запуске по расписанию
    сообщение приходит только при проблемах; при ручном запуске
    (ALWAYS_REPORT=true) отчёт приходит всегда.

Любая ошибка не роняет workflow.

Для точной проверки сбора workflow ai_watchdog.yml должен иметь в permissions
строку `actions: read`. Без неё скрипт работает по запасному варианту (git).
"""
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.join(os.path.dirname(__file__), "..")
OUT = os.path.join(ROOT, "output")

MIN_POOL = 30              # серверов в output/raw_servers.txt
MIN_MAIN = 20              # серверов в основной подписке
MIN_SECOND = 5             # серверов во второй подписке
MAX_COLLECT_AGE_HOURS = 3  # последний успешный сбор старше этого — сбор завис
MAX_RAW_AGE_FALLBACK = 8   # запасной вариант: возраст raw_servers.txt по git
COLLECT_WORKFLOW = "collect_and_test.yml"

# (адрес, список моделей). Пробуем по порядку, пока кто-то не ответит.
AI_ENDPOINTS = [
    ("https://models.github.ai/inference/chat/completions",
     [os.environ.get("AI_MODEL") or "openai/gpt-4o-mini"]),
    ("https://models.inference.ai.azure.com/chat/completions", ["gpt-4o-mini"]),
]
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


def last_collect_age_hours():
    """Часов с последнего УСПЕШНОГО запуска сбора (GitHub API). None, если не вышло."""
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        return None
    url = ("https://api.github.com/repos/%s/actions/workflows/%s/runs?status=success&per_page=1"
           % (repo, COLLECT_WORKFLOW))
    try:
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        runs = data.get("workflow_runs", [])
        if not runs:
            return None
        ts = runs[0].get("updated_at") or runs[0].get("run_started_at")
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
    except Exception as e:
        print("GitHub API недоступен (%s), проверяю по git." % e)
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
        "main_vless": sum(1 for ln in main if ln.startswith("vless://")),
        "main_trojan": sum(1 for ln in main if ln.startswith("trojan://")),
        "second": len(second),
        "collect_age_hours": last_collect_age_hours(),
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

    collect_age = s["collect_age_hours"]
    raw_age = s["raw_age_hours"]
    if collect_age is not None:
        if collect_age > MAX_COLLECT_AGE_HOURS:
            problems.append("Последний успешный сбор был %.1f ч назад (порог %d ч)"
                            % (collect_age, MAX_COLLECT_AGE_HOURS))
    elif raw_age is None:
        problems.append("Не удалось определить, когда последний раз менялся raw_servers.txt")
    elif raw_age > MAX_RAW_AGE_FALLBACK:
        problems.append("raw_servers.txt не менялся %.1f ч (порог %d ч)"
                        % (raw_age, MAX_RAW_AGE_FALLBACK))
    return problems


def ask_one(url, model, system, user):
    token = os.environ.get("GITHUB_TOKEN", "")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
        "max_tokens": 300,
    }
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if "github.ai" in url:
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
    with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
        status = resp.status
        text = resp.read().decode("utf-8", "replace")
    if not text.strip():
        raise RuntimeError("пустой ответ, HTTP %s" % status)
    try:
        data = json.loads(text)
    except Exception:
        raise RuntimeError("не JSON, HTTP %s: %s" % (status, text[:120].replace("\n", " ")))
    try:
        return (data["choices"][0]["message"]["content"] or "").strip()
    except Exception:
        raise RuntimeError("нет choices: " + text[:120].replace("\n", " "))


def ai_comment(stats, problems):
    """Возвращает (комментарий, ошибка). Если ИИ ответил, ошибка пустая."""
    if not os.environ.get("GITHUB_TOKEN"):
        return "", "нет GITHUB_TOKEN"
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
    errors = []
    for url, models in AI_ENDPOINTS:
        host = url.split("/")[2]
        for model in models:
            try:
                text = ask_one(url, model, system, user)
                if text:
                    return text, ""
                errors.append("%s %s: пустой комментарий" % (host, model))
            except urllib.error.HTTPError as e:
                try:
                    detail = e.read().decode("utf-8", "ignore")[:120].replace("\n", " ")
                except Exception:
                    detail = ""
                errors.append("%s: HTTP %s %s" % (host, e.code, detail))
            except Exception as e:
                errors.append("%s: %s" % (host, e))
    print("ИИ недоступен: " + " | ".join(errors))
    return "", " | ".join(errors)[:600]


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


def build_message(stats, problems, comment, ai_error):
    collect_age = stats["collect_age_hours"]
    raw_age = stats["raw_age_hours"]
    ooni = stats["ooni_pressure"]
    lines = [
        "⚠️ KoteitoVPN: есть проблемы" if problems else "✅ KoteitoVPN: всё в норме",
        "",
        "Пул (raw_servers): %d" % stats["pool"],
        "Основная подписка: %d (VLESS: %d, Trojan: %d, Hysteria2: %d, Reality: %d)"
        % (stats["main"], stats["main_vless"], stats["main_trojan"],
           stats["main_hy2"], stats["main_reality"]),
        "Вторая подписка: %d" % stats["second"],
    ]
    if collect_age is not None:
        lines.append("Последний успешный сбор: %.1f ч назад" % collect_age)
    else:
        lines.append("raw_servers.txt менялся (по git): %s"
                     % ("%.1f ч назад" % raw_age if raw_age is not None else "неизвестно"))
    lines.append("Давление блокировок OONI: %s" % ("%s%%" % ooni if ooni is not None else "нет данных"))
    if problems:
        lines += ["", "Проблемы:"] + ["- " + p for p in problems]
    if comment:
        lines += ["", "Комментарий ИИ:", comment]
    elif ai_error:
        lines += ["", "ИИ недоступен: " + ai_error]
    return "\n".join(lines)


def main():
    stats = collect_stats()
    problems = find_problems(stats)
    always = os.environ.get("ALWAYS_REPORT", "").lower() == "true"

    if not problems and not always:
        print("Всё в норме, сообщение не отправляется: %s" % json.dumps(stats, ensure_ascii=False))
        return

    comment, ai_error = ("", "")
    if problems:
        comment, ai_error = ai_comment(stats, problems)
    send_telegram(build_message(stats, problems, comment, ai_error))
    print("Отчёт отправлен.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Сторож: непредвиденная ошибка (%s)." % e)
