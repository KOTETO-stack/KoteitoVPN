#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_reports.py
Собирает подтверждения "работает" от доверенной группы людей через Telegram,
И теперь также отвечает на произвольные вопросы про подписку через Groq AI.

Как бот различает подтверждение и вопрос:
 - Если текст сообщения точно совпадает с именем одного из серверов, которые
   сейчас реально есть в output/subscription_readable.txt — это подтверждение
   "работает" (как раньше, без изменений).
 - Если текст не совпадает ни с одним именем сервера — это вопрос. Бот
   собирает короткую статистику текущей подписки (сколько серверов, по
   протоколам) и отправляет вопрос + эту статистику в Groq (chat completion,
   OpenAI-совместимый API), а полученный ответ пересылает обратно в Telegram.

Нужные секреты в GitHub Actions:
 - TELEGRAM_BOT_TOKEN     (уже есть)
 - ALLOWED_REPORTER_IDS   (уже есть)
 - GROQ_API_KEY           (новый — ключ от console.groq.com/keys)
   ВАЖНО: если ключ Groq раньше был где-то показан открытым текстом (в чате,
   в скриншоте) — он скомпрометирован. Прежде чем вставлять сюда, зайдите на
   console.groq.com/keys и создайте НОВЫЙ ключ, старый удалите.

Про Groq: используется эндпоинт /openai/v1/chat/completions (OpenAI-совместимый).
GROQ_MODEL можно сменить ниже, если модель отключат/переименуют на стороне Groq.
"""
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
REPORTS_FILE = os.path.join(OUT_DIR, "server_reports.json")
OFFSET_FILE = os.path.join(OUT_DIR, "telegram_offset.json")
READABLE_FILE = os.path.join(OUT_DIR, "subscription_readable.txt")

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
GROQ_MODEL = "llama-3.3-70b-versatile"
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


def load_known_server_names():
    """Читает текущий output/subscription_readable.txt и достаёт из каждой
    строки display_name (часть после последнего '#', URL-декодированная)."""
    names = set()
    if not os.path.exists(READABLE_FILE):
        return names
    with open(READABLE_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "#" not in line:
                continue
            name = urllib.parse.unquote(line.rsplit("#", 1)[1])
            names.add(name)
    return names


def build_subscription_context():
    """Короткая статистика текущей подписки для системного промпта Groq —
    чтобы бот отвечал по факту, а не придумывал цифры."""
    if not os.path.exists(READABLE_FILE):
        return "Данных о текущей подписке пока нет."
    proto_counts = {}
    total = 0
    with open(READABLE_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "://" not in line:
                continue
            proto = line.split("://", 1)[0].lower()
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
            total += 1
    parts = ", ".join(f"{p}: {c}" for p, c in sorted(proto_counts.items()))
    return f"Всего серверов в подписке: {total}. По протоколам: {parts}."


def get_updates(offset):
    if not BOT_TOKEN:
        print("TELEGRAM_BOT_TOKEN не задан — пропускаю сбор.")
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


def send_message(chat_id, text):
    if not BOT_TOKEN:
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    body = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=body, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except Exception as e:
        print(f"Не удалось отправить ответ в Telegram: {e}")


def ask_groq(question, context):
    if not GROQ_API_KEY:
        return "Groq не настроен (нет GROQ_API_KEY), не могу ответить на вопрос."
    system_prompt = (
        "Ты — бот проекта KoteitoVPN, помогаешь небольшой доверенной группе людей "
        "разобраться с подпиской VPN (Trojan/VLESS/Hysteria2 для Karing и Hiddyfi). "
        "Отвечай кратко, по-русски, только по фактам из контекста ниже. Если не "
        "знаешь ответа точно — прямо скажи, что не уверен, не выдумывай цифры.\n\n"
        f"Текущий контекст подписки: {context}"
    )
    body = json.dumps({
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
        "max_tokens": 500,
        "temperature": 0.3,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[groq error] {e}")
        return "Не удалось получить ответ от Groq (ошибка запроса), попробуйте позже."


def main():
    if not ALLOWED_IDS:
        print("ALLOWED_REPORTER_IDS не задан — сообщения никого не принимаются.")

    offset_state = load_json(OFFSET_FILE, {"last_update_id": 0})
    reports = load_json(REPORTS_FILE, {})
    known_names = load_known_server_names()
    context = build_subscription_context()

    updates = get_updates(offset_state.get("last_update_id", 0) + 1)
    max_update_id = offset_state.get("last_update_id", 0)
    accepted_reports = 0
    answered_questions = 0
    ignored = 0

    now_iso = datetime.now(timezone.utc).isoformat()

    for update in updates:
        update_id = update.get("update_id", 0)
        max_update_id = max(max_update_id, update_id)

        msg = update.get("message")
        if not msg:
            continue

        sender_id = str(msg.get("from", {}).get("id", ""))
        chat_id = msg.get("chat", {}).get("id")
        text = (msg.get("text") or "").strip()

        if sender_id not in ALLOWED_IDS or not text:
            ignored += 1
            continue

        if text in known_names:
            entry = reports.setdefault(text, {"ok_count": 0, "last_ok": None})
            entry["ok_count"] += 1
            entry["last_ok"] = now_iso
            accepted_reports += 1
        else:
            answer = ask_groq(text, context)
            send_message(chat_id, answer)
            answered_questions += 1

    save_json(REPORTS_FILE, reports)
    save_json(OFFSET_FILE, {"last_update_id": max_update_id})

    print(f"Обработано сообщений: {len(updates)}, подтверждений: {accepted_reports}, "
          f"вопросов отвечено: {answered_questions}, игнорировано: {ignored}.")


if __name__ == "__main__":
    main()
