#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
announce_status.py

Раз в час отправляет в Telegram сводку по подписке:
 - точное время сейчас и время СЛЕДУЮЩЕГО обновления подписки (берётся из cron-расписания
   workflow с именем UPDATE_WORKFLOW_NAME, время показывается в часовом поясе TZ_NAME);
 - точное число серверов в подписке;
 - протоколы: сколько всего и сколько серверов на каждом;
 - страны: сколько всего и сколько серверов в каждой (по флагу в названии сервера).

Если секреты TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID не заданы — тихо завершается без
ошибки (текст сводки при этом всё равно печатается в лог).
"""
import collections
import datetime
import glob
import os
import re
import urllib.parse
import urllib.request

ROOT = os.path.join(os.path.dirname(__file__), "..")
SUB_READABLE = os.path.join(ROOT, "output", "subscription_readable.txt")
WORKFLOWS_DIR = os.path.join(ROOT, ".github", "workflows")

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# Значение поля name: в yml того workflow, по расписанию которого обновляется подписка.
UPDATE_WORKFLOW_NAME = "Collect and Test VPN Sources"
# Часовой пояс для показа времени (МСК = UTC+3). Хочешь другой — поменяй две строки.
TZ_OFFSET_HOURS = 3
TZ_NAME = "МСК"

PROTO_NAMES = {
    "vless": "VLESS",
    "trojan": "Trojan",
    "hysteria2": "Hysteria2",
    "hy2": "Hysteria2",
    "vmess": "VMess",
    "ss": "Shadowsocks",
}

COUNTRY_NAMES = {
    "US": "США", "DE": "Германия", "NL": "Нидерланды", "FR": "Франция", "GB": "Великобритания",
    "SE": "Швеция", "FI": "Финляндия", "PL": "Польша", "RU": "Россия", "TR": "Турция",
    "JP": "Япония", "SG": "Сингапур", "HK": "Гонконг", "KR": "Южная Корея", "TW": "Тайвань",
    "CA": "Канада", "CH": "Швейцария", "AT": "Австрия", "IT": "Италия", "ES": "Испания",
    "CZ": "Чехия", "RO": "Румыния", "BG": "Болгария", "UA": "Украина", "LV": "Латвия",
    "LT": "Литва", "EE": "Эстония", "AM": "Армения", "KZ": "Казахстан", "GE": "Грузия",
    "IN": "Индия", "AU": "Австралия", "BR": "Бразилия", "AE": "ОАЭ", "IL": "Израиль",
    "NO": "Норвегия", "DK": "Дания", "IE": "Ирландия", "BE": "Бельгия", "PT": "Португалия",
    "HU": "Венгрия", "RS": "Сербия", "MD": "Молдова", "BY": "Беларусь", "AZ": "Азербайджан",
    "UZ": "Узбекистан", "IR": "Иран", "TH": "Таиланд", "VN": "Вьетнам", "ID": "Индонезия",
    "MY": "Малайзия", "PH": "Филиппины", "MX": "Мексика", "AR": "Аргентина", "ZA": "ЮАР",
    "CL": "Чили", "LU": "Люксембург", "GR": "Греция", "SK": "Словакия", "SI": "Словения",
    "HR": "Хорватия", "IS": "Исландия", "CY": "Кипр", "MT": "Мальта", "NZ": "Новая Зеландия",
    "EG": "Египет", "PK": "Пакистан", "BD": "Бангладеш", "KG": "Киргизия", "MN": "Монголия",
    "CO": "Колумбия", "PE": "Перу", "AL": "Албания", "MK": "Северная Македония",
    "BA": "Босния и Герцеговина", "ME": "Черногория", "LI": "Лихтенштейн",
}

FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")


# ---------------------------------------------------------------------
#                       расписание (cron) -> следующий запуск
# ---------------------------------------------------------------------
def parse_cron_field(expr, lo, hi):
    """Разбирает одно поле cron: *, */n, a-b, a-b/n, a/n, списки через запятую."""
    values = set()
    for part in expr.split(","):
        step = 1
        has_step = False
        if "/" in part:
            part, step_s = part.split("/", 1)
            step = int(step_s)
            has_step = True
        if part == "*":
            start, end = lo, hi
        elif "-" in part:
            a, b = part.split("-", 1)
            start, end = int(a), int(b)
        else:
            start = int(part)
            end = hi if has_step else start
        values.update(range(start, end + 1, step))
    return values


def next_cron_run(cron, after):
    """Ближайший запуск строго после `after` (UTC), либо None."""
    fields = cron.split()
    if len(fields) != 5:
        return None
    try:
        minutes = parse_cron_field(fields[0], 0, 59)
        hours = parse_cron_field(fields[1], 0, 23)
        doms = parse_cron_field(fields[2], 1, 31)
        months = parse_cron_field(fields[3], 1, 12)
        dows = {v % 7 for v in parse_cron_field(fields[4], 0, 7)}
    except Exception:
        return None
    dom_star = fields[2].startswith("*")
    dow_star = fields[4].startswith("*")

    t = after.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    for _ in range(366 * 24 * 60):
        if t.month in months and t.hour in hours and t.minute in minutes:
            dom_ok = t.day in doms
            dow_ok = ((t.weekday() + 1) % 7) in dows  # в cron воскресенье = 0
            if dom_star or dow_star:
                day_ok = dom_ok and dow_ok
            else:
                day_ok = dom_ok or dow_ok
            if day_ok:
                return t
        t += datetime.timedelta(minutes=1)
    return None


def find_crons():
    """Все cron-выражения из workflow с именем UPDATE_WORKFLOW_NAME."""
    crons = []
    for path in sorted(glob.glob(os.path.join(WORKFLOWS_DIR, "*.y*ml"))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        except Exception:
            continue
        m = re.search(r"^name:\s*(.+?)\s*$", text, re.M)
        name = m.group(1).strip("'\"") if m else ""
        if name != UPDATE_WORKFLOW_NAME:
            continue
        crons += re.findall(r"^\s*-\s*cron:\s*['\"]([^'\"]+)['\"]", text, re.M)
    return crons


def fmt_delta(minutes):
    if minutes < 60:
        return "%d мин" % minutes
    return "%d ч %02d мин" % (minutes // 60, minutes % 60)


def next_update_line(now_utc, tz):
    crons = find_crons()
    runs = [r for r in (next_cron_run(c, now_utc) for c in crons) if r]
    if not runs:
        return "🔄 Следующее обновление: расписание не найдено"
    nxt = min(runs)
    local = nxt.astimezone(tz)
    now_local = now_utc.astimezone(tz)
    if local.date() == now_local.date():
        when = local.strftime("%H:%M")
    else:
        when = local.strftime("%d.%m %H:%M")
    minutes = int((nxt - now_utc).total_seconds() // 60)
    return "🔄 Следующее обновление: %s %s (через %s; GitHub иногда опаздывает на 5–30 мин)" % (
        when, TZ_NAME, fmt_delta(minutes))


# ---------------------------------------------------------------------
#                              Telegram
# ---------------------------------------------------------------------
def send_telegram(text):
    if not BOT_TOKEN or not CHAT_ID:
        print("TELEGRAM_BOT_TOKEN/CHAT_ID не заданы — пропускаем уведомление.")
        return
    url = "https://api.telegram.org/bot%s/sendMessage" % BOT_TOKEN
    data = urllib.parse.urlencode({"chat_id": CHAT_ID, "text": text}).encode()
    try:
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
        print("Отправлено в Telegram.")
    except Exception as e:
        print("Не удалось отправить в Telegram: %s" % e)


# ---------------------------------------------------------------------
#                             разбор подписки
# ---------------------------------------------------------------------
def country_of(remark):
    """(флаг, код страны) из названия сервера, либо ('', '')."""
    m = FLAG_RE.search(remark)
    if not m:
        return "", ""
    flag = m.group(0)
    code = "".join(chr(ord(c) - 0x1F1E6 + 65) for c in flag)
    return flag, code


def main():
    tz = datetime.timezone(datetime.timedelta(hours=TZ_OFFSET_HOURS))
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_local = now_utc.astimezone(tz)

    if not os.path.exists(SUB_READABLE):
        send_telegram("⚠️ KoteitoVPN: output/subscription_readable.txt пока не существует — "
                      "подписка ещё не собиралась.")
        return

    with open(SUB_READABLE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    proto_counts = collections.Counter()
    country_counts = collections.Counter()
    country_labels = {}
    total = 0

    for line in lines:
        if "://" not in line:
            continue
        scheme = line.split("://", 1)[0].lower()
        if scheme not in PROTO_NAMES:
            continue
        total += 1
        proto_counts[PROTO_NAMES[scheme]] += 1

        remark = urllib.parse.unquote(line.split("#", 1)[1]) if "#" in line else ""
        flag, code = country_of(remark)
        if code:
            country_counts[code] += 1
            country_labels[code] = "%s %s" % (flag, COUNTRY_NAMES.get(code, code))
        else:
            country_counts["??"] += 1
            country_labels["??"] = "🌐 Без флага"

    out = [
        "📊 KoteitoVPN — статус подписки",
        "🕒 Сейчас: %s %s" % (now_local.strftime("%d.%m.%Y %H:%M"), TZ_NAME),
        next_update_line(now_utc, tz),
        "",
        "🖥 Серверов в подписке: %d" % total,
        "",
        "🔌 Протоколов: %d" % len(proto_counts),
    ]
    for name, n in proto_counts.most_common():
        out.append("  • %s: %d" % (name, n))

    real_countries = [c for c in country_counts if c != "??"]
    out.append("")
    out.append("🌍 Стран: %d" % len(real_countries))
    for code, n in sorted(country_counts.items(), key=lambda kv: (-kv[1], country_labels[kv[0]])):
        out.append("  %s — %d" % (country_labels[code], n))

    text = "\n".join(out)[:4000]
    print(text)
    send_telegram(text)


if __name__ == "__main__":
    main()
