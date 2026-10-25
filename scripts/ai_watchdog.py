#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_watchdog.py (версия 3)

Сторож подписки. ТОЛЬКО ЧИТАЕТ файлы репозитория и пишет в Telegram,
в репозиторий ничего не меняет.

Что делает:
 1. Считает серверы: пул (output/raw_servers.txt), основная и вторая подписки.
 2. Через GitHub API смотрит, когда последний раз успешно отработали
    сбор, сборка подписок, проверка из РФ и ИИ-советчик (если API недоступен,
    для сбора используется возраст raw_servers.txt по истории git).
 3. Читает покрытие проверки из РФ (output/ru_probe.json), число правил
    ИИ-советчика (output/ai_advice.json) и индикатор давления блокировок OONI.
 4. Если есть проблемы, просит бесплатную модель GitHub Models коротко
    объяснить вероятную причину. Модель получает только цифры, которые посчитал
    сам скрипт. Если модель недоступна, причина попадает в отчёт.
 5. Отправляет сообщение в Telegram: при проблемах; раз в сутки утром
    (по расписанию, 06-08 UTC) как проверка, что сам сторож жив; при ручном
    запуске (ALWAYS_REPORT=true) всегда.

Сторож проверяет сборку, а не работу серверов на конкретной сети: это видно
только в приложении. Любая ошибка не роняет workflow.

Для проверки запусков в permissions workflow ai_watchdog.yml нужна строка
`actions: read`.
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
MAX_RAW_AGE_FALLBACK = 8   # запасной вариант для сбора: возраст raw_servers.txt по git, ч

# (файл workflow, название, максимальный возраст последнего успешного запуска, ч)
WORKFLOW_CHECKS = [
    ("collect_and_test.yml", "Сбор серверов", 3),
    ("build_subscription.yml", "Сборка подписок", 3),
    ("ru_probe.yml", "Проверка из РФ", 8),
    ("ai_advisor.yml", "ИИ-советчик", 30),
]

HEARTBEAT_HOURS_UTC = (6, 7, 8)   # суточный отчёт «сторож жив»
PROBE_TTL_HOURS = 48

AI_URL = "https://models.github.ai/inference/chat/completions"
AI_MODEL = os.environ.get("AI_MODEL") or "openai/gpt-4o-mini"
AI_API_VERSIONS = ["2026-03-10", "2022-11-28"]
AI_TIMEOUT = 60


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Не идём за редиректами молча: так видно, куда сервер отправляет запрос."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


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


def last_success_age_hours(workflow):
    """Часов с последнего УСПЕШНОГО запуска workflow (GitHub API) или None."""
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        return None
    url = ("https://api.github.com/repos/%s/actions/workflows/%s/runs?status=success&per_page=1"
           % (repo, workflow))
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
    except urllib.error.HTTPError as e:
        print("GitHub API (%s): HTTP %s" % (workflow, e.code))
        return None
    except Exception as e:
        print("GitHub API (%s) недоступен: %s" % (workflow, e))
        return None


def load_ooni_pressure():
    try:
        with open(os.path.join(OUT, "ooni_censorship_index.json"), "r", encoding="utf-8") as f:
            return json.load(f).get("pressure_percent")
    except Exception:
        return None


def probe_key(line):
    try:
        u = urllib.parse.urlparse(line)
        if (u.scheme or "").lower() not in ("vless", "trojan"):
            return None
        if not u.hostname or not u.port:
            return None
        return "%s:%d" % (u.hostname.lower(), u.port)
    except Exception:
        return None


def probe_coverage(sub_lines):
    """(vless/trojan в подписках, с свежей проверкой из РФ, недоступно из РФ) или None."""
    try:
        with open(os.path.join(OUT, "ru_probe.json"), "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
    except Exception:
        return None
    keys = set()
    for line in sub_lines:
        k = probe_key(line)
        if k:
            keys.add(k)
    now = time.time()
    fresh = bad = 0
    for k in keys:
        e = data.get(k)
        if not isinstance(e, dict):
            continue
        try:
            if now - float(e.get("t", 0)) > PROBE_TTL_HOURS * 3600:
                continue
            fresh += 1
            if int(e.get("total", 0)) > 0 and int(e.get("ok", 0)) == 0:
                bad += 1
        except (TypeError, ValueError):
            continue
    return len(keys), fresh, bad


def advice_rules_count():
    try:
        with open(os.path.join(OUT, "ai_advice.json"), "r", encoding="utf-8") as f:
            return len(json.load(f).get("rules", []))
    except Exception:
        return None


def collect_stats():
    pool = read_lines(os.path.join(OUT, "raw_servers.txt"))
    main = read_lines(os.path.join(OUT, "subscription_readable.txt"))
    second = read_lines(os.path.join(OUT, "subscription_cellular_readable.txt"))
    ages = {wf: last_success_age_hours(wf) for wf, _name, _max in WORKFLOW_CHECKS}
    return {
        "pool": len(pool),
        "main": len(main),
        "main_hy2": sum(1 for ln in main if ln.startswith(("hysteria2://", "hy2://"))),
        "main_reality": sum(1 for ln in main if "security=reality" in ln),
        "main_vless": sum(1 for ln in main if ln.startswith("vless://")),
        "main_trojan": sum(1 for ln in main if ln.startswith("trojan://")),
        "second": len(second),
        "ages": ages,
        "raw_age_hours": last_commit_age_hours("output/raw_servers.txt"),
        "probe": probe_coverage(main + second),
        "advice_rules": advice_rules_count(),
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

    for wf, name, max_h in WORKFLOW_CHECKS:
        age = s["ages"].get(wf)
        if age is not None:
            if age > max_h:
                problems.append("%s: последний успешный запуск %.1f ч назад (порог %d ч)"
                                % (name, age, max_h))
        elif wf == "collect_and_test.yml":
            raw_age = s["raw_age_hours"]
            if raw_age is None:
                problems.append("Не удалось определить, когда последний раз менялся raw_servers.txt")
            elif raw_age > MAX_RAW_AGE_FALLBACK:
                problems.append("raw_servers.txt не менялся %.1f ч (порог %d ч)"
                                % (raw_age, MAX_RAW_AGE_FALLBACK))
    return problems


def ask_one(api_version, system, user):
    token = os.environ.get("GITHUB_TOKEN", "")
    payload = {
        "model": AI_MODEL,
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
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": api_version,
    }
    req = urllib.request.Request(AI_URL, data=json.dumps(payload).encode("utf-8"), headers=headers)
    try:
        with OPENER.open(req, timeout=AI_TIMEOUT) as resp:
            status = resp.status
            ctype = resp.headers.get("Content-Type", "")
            text = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "ignore")[:100].replace("\n", " ")
        except Exception:
            detail = ""
        loc = e.headers.get("Location", "") if e.headers else ""
        raise RuntimeError("HTTP %s%s %s" % (e.code, (" -> " + loc) if loc else "", detail))
    if not text.strip():
        raise RuntimeError("пустой ответ, HTTP %s, тип %s" % (status, ctype))
    try:
        data = json.loads(text)
    except Exception:
        raise RuntimeError("не JSON, HTTP %s, тип %s, тело: %s"
                           % (status, ctype, " ".join(text.split())[:100]))
    try:
        return (data["choices"][0]["message"]["content"] or "").strip()
    except Exception:
        raise RuntimeError("нет choices: " + " ".join(text.split())[:100])


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
        "проверяет их и пишет raw_servers.txt; затем build_subscription "
        "собирает основную и вторую подписки."
    )
    errors = []
    for ver in AI_API_VERSIONS:
        try:
            text = ask_one(ver, system, user)
            if text:
                return text, ""
            errors.append("v%s: пустой комментарий" % ver)
        except Exception as e:
            errors.append("v%s: %s" % (ver, e))
    print("ИИ недоступен: " + " | ".join(errors))
    return "", " | ".join(errors)[:500]


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


def fmt_age(h):
    return "%.1f ч назад" % h if h is not None else "нет данных"


def build_message(stats, problems, comment, ai_error):
    ooni = stats["ooni_pressure"]
    lines = [
        "⚠️ KoteitoVPN: проблемы со сборкой" if problems else "✅ KoteitoVPN: сборка идёт штатно",
        "",
        "Пул (raw_servers): %d" % stats["pool"],
        "Основная подписка: %d (VLESS: %d, Trojan: %d, Hysteria2: %d, Reality: %d)"
        % (stats["main"], stats["main_vless"], stats["main_trojan"],
           stats["main_hy2"], stats["main_reality"]),
        "Вторая подписка: %d" % stats["second"],
        "",
    ]
    for wf, name, _max in WORKFLOW_CHECKS:
        age = stats["ages"].get(wf)
        if age is None and wf == "collect_and_test.yml":
            lines.append("%s: raw_servers.txt менялся (по git) %s" % (name, fmt_age(stats["raw_age_hours"])))
        else:
            lines.append("%s: %s" % (name, fmt_age(age)))
    probe = stats["probe"]
    if probe:
        total, fresh, bad = probe
        lines.append("Проверка из РФ: проверено %d из %d серверов подписок, недоступно %d"
                     % (fresh, total, bad))
    else:
        lines.append("Проверка из РФ: данных пока нет")
    rules = stats["advice_rules"]
    lines.append("Советы ИИ: %s" % ("правил %d" % rules if rules is not None else "файла пока нет"))
    lines.append("Давление блокировок OONI: %s" % ("%s%%" % ooni if ooni is not None else "нет данных"))
    if problems:
        lines += ["", "Проблемы:"] + ["- " + p for p in problems]
    if comment:
        lines += ["", "Комментарий ИИ:", comment]
    elif ai_error:
        lines += ["", "ИИ недоступен: " + ai_error]
    lines += ["", "Это проверка сборки. Как серверы работают на вашей сети, видно только в приложении."]
    return "\n".join(lines)


def main():
    stats = collect_stats()
    problems = find_problems(stats)
    always = os.environ.get("ALWAYS_REPORT", "").lower() == "true"
    scheduled = os.environ.get("GITHUB_EVENT_NAME", "") == "schedule"
    heartbeat = scheduled and datetime.now(timezone.utc).hour in HEARTBEAT_HOURS_UTC

    if not problems and not always and not heartbeat:
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
