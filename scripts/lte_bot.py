#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lte_bot.py
Телеграм-бот для замеров на мобильной сети. Ты пишешь боту, какие серверы зелёные и какие
красные, он сам дописывает lte_results.txt и чистит старое. Бот не висит на сервере:
workflow lte_bot.yml раз в 5 минут забирает новые сообщения (getUpdates), правит файлы,
коммитит их и только после этого отвечает.

Два режима запуска:
  python scripts/lte_bot.py process   забрать сообщения, обновить файлы, подготовить ответы
  python scripts/lte_bot.py send      отправить подготовленные ответы (после успешного коммита)

Секреты: LTE_BOT_TOKEN (токен нового бота от @BotFather) и TELEGRAM_CHAT_ID (твой id, уже есть;
можно задать отдельный LTE_BOT_ALLOWED со списком id через запятую). Сообщения от других людей
игнорируются, кроме команды /start или /id: на неё бот отвечает id отправителя.

Что понимает (одна строка = один сервер, можно присылать несколько строк в одном сообщении):
  з 45.145.43.151:443 86        зелёный сервер по адресу, число = мс (необязательно)
  к 94.183.206.83:2087          красный сервер по адресу
  з Германия Оффенбах 86        то же по названию из Karing (бот ищет его в подписках)
  к США Чикаго #2               #1 или #2 ограничивает поиск первой или второй подпиской
  остальные красные #1          все серверы подписки 1, которых нет среди зелёных в этом сообщении
Буквы цвета: з, g, + для зелёного; к, r, - для красного.
Команды: /help, /last [N], /stats, /undo (убрать записи последнего сообщения), /clean.

Чистка: у каждого сервера хранятся только последние KEEP_PER_SERVER замеров, записи старше
MAX_AGE_DAYS дней (если дату можно прочитать из метки) удаляются. Удалённое не пропадает, а
дописывается в data/lte_results_archive.txt.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS = os.path.join(ROOT, "lte_results.txt")
ARCHIVE = os.path.join(ROOT, "data", "lte_results_archive.txt")
STATE_FILE = os.path.join(ROOT, "data", "lte_bot_state.json")
OUTBOX = os.path.join(ROOT, ".cache", "lte_bot_outbox.json")
OUT_DIR = os.path.join(ROOT, "output")

KEEP_PER_SERVER = 3          # сколько последних замеров хранить у каждого сервера
MAX_AGE_DAYS = 30            # записи старше удаляются (если в метке есть читаемая дата)
ARCHIVE_MAX_LINES = 5000     # архив длиннее этого обрезается с начала
TZ = timezone(timedelta(hours=3))   # время в метках: Москва
MAX_AMBIGUOUS_SHOWN = 6
RECENT_GREEN_HOURS = 12      # «остальные красные» не трогает серверы, зелёные за последние столько часов

GREEN_WORDS = {"з", "g", "+", "зел", "зелёный", "зеленый", "green", "ok", "ок"}
RED_WORDS = {"к", "r", "-", "кр", "красный", "red"}

HELP = (
    "Пиши замеры строками, одна строка = один сервер:\n\n"
    "з 45.145.43.151:443 86   (зелёный, адрес, мс по желанию)\n"
    "к 94.183.206.83:2087      (красный)\n"
    "з Германия Оффенбах 86   (по названию из Karing)\n"
    "к США Чикаго #2           (#1 или #2 = только первая или вторая подписка)\n"
    "остальные красные #1      (все остальные серверы подписки 1 красные; те, что были зелёными "
    "за последние 12 часов, не трогаю)\n\n"
    "Цвет: з, g, + = зелёный; к, r, - = красный.\n"
    "Команды: /last [N] последние записи, /stats сводка, /undo убрать записи последнего "
    "сообщения, /clean почистить старое сейчас.\n"
    "Время записей считаю по Москве. Ответ приходит в течение 5-15 минут."
)


# =====================================================================
#                          Telegram
# =====================================================================
def api(token, method, params=None, timeout=30):
    url = "https://api.telegram.org/bot%s/%s" % (token, method)
    body = json.dumps(params or {}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    if not data.get("ok"):
        raise RuntimeError("Telegram: %s" % data.get("description", data))
    return data.get("result")


# =====================================================================
#                          файлы
# =====================================================================
def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().splitlines()
    except OSError:
        return []


def write_lines(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)


# =====================================================================
#                          подписки: название -> адрес
# =====================================================================
def subscription_files():
    """[(номер группы, путь)] для output/subscription_readable.txt, ..._cellular_readable.txt, ..._3_readable.txt."""
    out = [(1, os.path.join(OUT_DIR, "subscription_readable.txt")),
           (2, os.path.join(OUT_DIR, "subscription_cellular_readable.txt"))]
    n = 3
    while os.path.exists(os.path.join(OUT_DIR, "subscription_%d_readable.txt" % n)):
        out.append((n, os.path.join(OUT_DIR, "subscription_%d_readable.txt" % n)))
        n += 1
    return out


def norm_name(text):
    t = (text or "").lower().replace("ё", "е")
    t = re.sub(r"[^\w\s\-]", " ", t, flags=re.UNICODE)
    t = t.replace("_", " ")
    return re.sub(r"\s+", " ", t).strip()


def load_servers():
    """Серверы из текущих подписок: [{group, name, norm, addr, proto}]."""
    servers = []
    for group, path in subscription_files():
        for line in read_lines(path):
            if "://" not in line:
                continue
            try:
                u = urllib.parse.urlparse(line.strip())
                host, port = (u.hostname or "").lower(), u.port
            except ValueError:
                continue
            if not host or not port:
                continue
            name = urllib.parse.unquote(u.fragment).replace("\u2705", "").strip() or host
            servers.append({"group": group, "name": name, "norm": norm_name(name),
                            "addr": "%s:%d" % (host, port), "proto": (u.scheme or "").lower()})
    return servers


def find_servers(query, servers, group=None):
    """Серверы по названию: точное совпадение, затем начало названия, затем все слова."""
    q = norm_name(query)
    if not q:
        return []
    pool = [s for s in servers if group is None or s["group"] == group]
    for test in (lambda n: n == q, lambda n: n.startswith(q),
                 lambda n: all(w in n.split() or w in n for w in q.split())):
        hit = [s for s in pool if test(s["norm"])]
        if hit:
            seen, out = set(), []
            for s in hit:
                if s["addr"] not in seen:
                    seen.add(s["addr"])
                    out.append(s)
            return out
    return []


# =====================================================================
#                          разбор сообщения
# =====================================================================
ADDR_RE = re.compile(r"^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9._\-]+):(\d{1,5})$")
GROUP_RE = re.compile(r"#(\d+)")
REST_RE = re.compile(r"^(остальн\w*|rest)\s+(красн\w*|red|r|к)\b", re.IGNORECASE)


def parse_line(line):
    """-> dict(kind=..., ...) или None. kind: result | rest | unknown."""
    raw = line.strip()
    if not raw:
        return None
    group = None
    m = GROUP_RE.search(raw)
    if m:
        group = int(m.group(1))
        raw = (raw[:m.start()] + " " + raw[m.end():]).strip()
    if REST_RE.match(raw):
        return {"kind": "rest", "group": group}
    parts = raw.split(None, 1)
    first = parts[0].lower().rstrip(":.,")
    if first in GREEN_WORDS:
        res = "G"
    elif first in RED_WORDS:
        res = "R"
    else:
        return {"kind": "unknown", "text": line.strip()}
    rest = parts[1].strip() if len(parts) > 1 else ""
    if not rest:
        return {"kind": "unknown", "text": line.strip()}
    ms = ""
    m2 = re.match(r"^(.*\S)\s+(\d{2,5})\s*(?:мс|ms)?$", rest, re.IGNORECASE)
    if m2:
        rest, ms = m2.group(1), m2.group(2)
    tokens = rest.split()
    if tokens and ADDR_RE.match(tokens[0]):
        return {"kind": "result", "res": res, "addr": tokens[0].lower(), "ms": ms,
                "note": " ".join(tokens[1:]), "group": group}
    return {"kind": "result", "res": res, "query": rest, "ms": ms, "group": group}


def result_line(label, res, addr, desc, ms):
    clean = (desc or "").replace(";", ",").strip()
    return "%s;%s;%s;%s;%s" % (label, res, addr, clean, ms or "")


def handle_text(text, when, state, lines, servers):
    """Разбирает сообщение. Меняет lines. Возвращает текст ответа."""
    label = when.strftime("%Y-%m-%d %H:%M")
    stripped = text.strip()
    low = stripped.lower()

    if low.startswith("/start") or low.startswith("/help"):
        return HELP
    if low.startswith("/last"):
        m = re.search(r"\d+", stripped)
        n = min(int(m.group(0)), 40) if m else 10
        data = [l for l in lines if l.strip() and not l.startswith("#")]
        shown = data[-n:]
        if not shown:
            return "В lte_results.txt пока нет замеров."
        return "Последние записи (%d):\n" % len(shown) + "\n".join(
            "%s %s %s" % (l.split(";")[1] if l.count(";") >= 1 else "?",
                          l.split(";")[2] if l.count(";") >= 2 else "?", l.split(";")[0]) for l in shown)
    if low.startswith("/stats"):
        return stats_text(lines)
    if low.startswith("/undo"):
        batch = state.get("last_batch") or []
        if not batch:
            return "Нечего отменять: нет записей от последнего сообщения."
        removed = 0
        for b in batch:
            if b in lines:
                lines.remove(b)
                removed += 1
        state["last_batch"] = []
        return "Отменено записей: %d." % removed
    if low.startswith("/clean"):
        new, removed = prune(lines, when)
        lines[:] = new
        state["archive_add"] = state.get("archive_add", []) + removed
        return "Чистка выполнена: убрано записей %d (они в data/lte_results_archive.txt)." % len(removed)
    if low.startswith("/"):
        return "Не знаю такой команды. /help покажет, что я умею."

    parsed = [(ln, parse_line(ln)) for ln in stripped.splitlines() if ln.strip()]
    added, skipped, ambiguous, rest_cmds = [], [], [], []
    green_addrs, mentioned = set(), set()
    for ln, p in parsed:
        if p is None:
            continue
        if p["kind"] == "unknown":
            skipped.append(ln.strip())
        elif p["kind"] == "rest":
            rest_cmds.append(p)
        else:
            if "addr" in p:
                targets = [{"addr": p["addr"], "name": p.get("note") or "", "proto": ""}]
            else:
                found = find_servers(p["query"], servers, p.get("group"))
                if not found:
                    skipped.append("%s (не нашёл в подписках)" % ln.strip())
                    continue
                if len(found) > 1:
                    ambiguous.append((ln.strip(), found))
                    continue
                targets = [found[0]]
            for t in targets:
                desc = (t["name"] + (" " + t["proto"] if t.get("proto") else "")).strip()
                new_line = result_line(label, p["res"], t["addr"], desc, p["ms"])
                if new_line not in lines and new_line not in added:
                    added.append(new_line)
                mentioned.add(t["addr"])
                if p["res"] == "G":
                    green_addrs.add(t["addr"])
    rest_count = 0
    protected = recent_green(lines + added, when) if rest_cmds else set()
    for cmd in rest_cmds:
        for s in servers:
            if cmd["group"] is not None and s["group"] != cmd["group"]:
                continue
            if s["addr"] in mentioned or s["addr"] in protected:
                continue
            desc = ("остальные красные: %s %s" % (s["name"], s["proto"])).strip()
            new_line = result_line(label, "R", s["addr"], desc, "")
            if new_line not in lines and new_line not in added:
                added.append(new_line)
                rest_count += 1
            mentioned.add(s["addr"])

    if added:
        lines.extend(added)
        state["last_batch"] = added
    g = sum(1 for a in added if a.split(";")[1] == "G")
    r = len(added) - g
    reply = []
    if added:
        reply.append("Записано: зелёных %d, красных %d%s." % (
            g, r, " (из них по «остальные красные»: %d)" % rest_count if rest_count else ""))
        if len(lines) > 0:
            new, removed = prune(lines, when)
            if removed:
                lines[:] = new
                state["archive_add"] = state.get("archive_add", []) + removed
                reply.append("Старое почистил: убрано записей %d." % len(removed))
    for ln, found in ambiguous:
        opts = "; ".join("%s (подписка %d, %s)" % (s["addr"], s["group"], s["proto"])
                         for s in found[:MAX_AMBIGUOUS_SHOWN])
        reply.append("Под «%s» подходит несколько серверов: %s. Пришли строку с адресом или добавь #1 / #2." % (ln, opts))
    if skipped:
        reply.append("Не понял: " + "; ".join(skipped[:8]))
    if not reply:
        reply.append("Ничего не записал. /help покажет форматы.")
    return "\n".join(reply)


# =====================================================================
#                          чистка и сводка
# =====================================================================
LABEL_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
LABEL_DMY = re.compile(r"(?<!\d)(\d{1,2})\.(\d{1,2})(?:\.(\d{2,4}))?(?!\d)")


def label_date(label, today):
    m = LABEL_ISO.search(label)
    try:
        if m:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=TZ)
        m = LABEL_DMY.search(label)
        if m:
            day, mon = int(m.group(1)), int(m.group(2))
            year = int(m.group(3)) if m.group(3) else today.year
            if year < 100:
                year += 2000
            d = datetime(year, mon, day, tzinfo=TZ)
            if not m.group(3) and d > today + timedelta(days=1):
                d = datetime(year - 1, mon, day, tzinfo=TZ)
            return d
    except ValueError:
        return None
    return None


def parse_data_line(line):
    """-> (метка, G/R, адрес) или None (комментарий, пустая или битая строка)."""
    if not line.strip() or line.lstrip().startswith("#"):
        return None
    p = [x.strip() for x in line.split(";")]
    if len(p) < 3 or p[1].upper() not in ("G", "R"):
        return None
    host, _, port = p[2].rpartition(":")
    if not host or not port.isdigit():
        return None
    return p[0], p[1].upper(), "%s:%s" % (host.lower(), port)


def prune(lines, today):
    """-> (новые строки, убранные строки). Порядок строк сохраняется, комментарии и непонятные строки остаются."""
    parsed = [parse_data_line(l) for l in lines]
    by_addr = {}
    for i, p in enumerate(parsed):
        if p:
            by_addr.setdefault(p[2], []).append(i)
    drop = set()
    for addr, idx in by_addr.items():
        for i in idx[:-KEEP_PER_SERVER]:
            drop.add(i)
        dated = [(i, label_date(parsed[i][0], today)) for i in idx]
        newest = dated[-1][1]
        if newest is not None and (today - newest) > timedelta(days=MAX_AGE_DAYS):
            drop.update(i for i, _d in dated)
        else:
            for i, d in dated:
                if d is not None and (today - d) > timedelta(days=MAX_AGE_DAYS):
                    drop.add(i)
    keep = [l for i, l in enumerate(lines) if i not in drop]
    removed = [lines[i] for i in sorted(drop)]
    return keep, removed


LABEL_DT = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2}))?")


def recent_green(lines, when, hours=RECENT_GREEN_HOURS):
    """Адреса, чей последний замер зелёный и сделан не раньше чем hours часов назад.
    «Остальные красные» таких серверов не трогает."""
    last = {}
    for l in lines:
        p = parse_data_line(l)
        if p:
            last[p[2]] = (p[0], p[1])
    out = set()
    for addr, (label, res) in last.items():
        if res != "G":
            continue
        m = LABEL_DT.search(label)
        if not m:
            continue
        try:
            d = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                         int(m.group(4) or 23), int(m.group(5) or 59), tzinfo=TZ)
        except ValueError:
            continue
        if timedelta(0) <= (when - d) <= timedelta(hours=hours) or (d - when) > timedelta(0):
            out.add(addr)
    return out


def stats_text(lines):
    last = {}
    labels = []
    for l in lines:
        p = parse_data_line(l)
        if p:
            last.setdefault(p[2], []).append(p[1])
            labels.append(p[0])
    if not last:
        return "В lte_results.txt пока нет замеров."
    g = r = flaky = 0
    for results in last.values():
        if "G" in results and "R" in results:
            flaky += 1
        elif results[-1] == "G":
            g += 1
        else:
            r += 1
    return ("Замеров в файле: %d, серверов: %d.\nЗелёных %d, красных %d, мигающих %d.\nПоследний замер: %s."
            % (sum(len(v) for v in last.values()), len(last), g, r, flaky, labels[-1]))


# =====================================================================
#                          режимы
# =====================================================================
def allowed_ids():
    raw = os.environ.get("LTE_BOT_ALLOWED") or os.environ.get("TELEGRAM_CHAT_ID") or ""
    return {x.strip() for x in raw.split(",") if x.strip()}


def process(token=None):
    token = token or os.environ.get("LTE_BOT_TOKEN", "")
    if not token:
        print("lte_bot: секрет LTE_BOT_TOKEN не задан, пропускаю.")
        return
    state = load_state()
    try:
        updates = api(token, "getUpdates", {"offset": state.get("offset", 0), "timeout": 0,
                                            "allowed_updates": ["message"]})
    except Exception as e:
        print("lte_bot: не удалось получить сообщения (%s)" % e)
        return
    if not updates:
        print("lte_bot: новых сообщений нет.")
        return

    allowed = allowed_ids()
    lines = read_lines(RESULTS)
    original = list(lines)
    servers = load_servers()
    outbox = []
    state["archive_add"] = []
    max_id = state.get("offset", 0) - 1
    for u in updates:
        max_id = max(max_id, int(u.get("update_id", 0)))
        msg = u.get("message") or {}
        frm = str((msg.get("from") or {}).get("id", ""))
        chat = (msg.get("chat") or {}).get("id")
        text = msg.get("text") or msg.get("caption") or ""
        if frm not in allowed and str(chat) not in allowed:
            if text.strip().lower().startswith(("/start", "/id")) and chat is not None:
                outbox.append({"chat_id": chat, "text": "Доступ закрыт. Твой id: %s. Чтобы дать доступ, "
                               "добавь его в секрет LTE_BOT_ALLOWED в настройках репозитория." % frm})
            continue
        if chat is None:
            continue
        if not text:
            outbox.append({"chat_id": chat, "text": "Пока понимаю только текст. Скриншоты не разбираю: "
                           "пришли строки вида «з Германия Оффенбах 86»."})
            continue
        when = datetime.fromtimestamp(int(msg.get("date", 0)) or datetime.now(TZ).timestamp(), TZ)
        try:
            reply = handle_text(text, when, state, lines, servers)
        except Exception as e:
            reply = "Ошибка при разборе сообщения (%s). Записи не менял." % e
        outbox.append({"chat_id": chat, "text": reply[:3500]})

    state["offset"] = max_id + 1
    if lines != original:
        write_lines(RESULTS, lines)
    archive_add = state.pop("archive_add", [])
    if archive_add:
        arch = read_lines(ARCHIVE) + archive_add
        write_lines(ARCHIVE, arch[-ARCHIVE_MAX_LINES:])
    save_state(state)
    os.makedirs(os.path.dirname(OUTBOX), exist_ok=True)
    with open(OUTBOX, "w", encoding="utf-8") as f:
        json.dump(outbox, f, ensure_ascii=False)
    print("lte_bot: сообщений обработано %d, ответов подготовлено %d, строк в lte_results.txt %d."
          % (len(updates), len(outbox), len(lines)))


def send(token=None):
    token = token or os.environ.get("LTE_BOT_TOKEN", "")
    if not token or not os.path.exists(OUTBOX):
        print("lte_bot: отправлять нечего.")
        return
    try:
        with open(OUTBOX, "r", encoding="utf-8") as f:
            outbox = json.load(f)
    except (OSError, ValueError):
        outbox = []
    sent = 0
    for item in outbox:
        try:
            api(token, "sendMessage", {"chat_id": item["chat_id"], "text": item["text"]})
            sent += 1
        except Exception as e:
            print("lte_bot: ответ не отправлен (%s)" % e)
    try:
        os.remove(OUTBOX)
    except OSError:
        pass
    print("lte_bot: отправлено ответов %d из %d." % (sent, len(outbox)))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "process"
    try:
        if mode == "send":
            send()
        else:
            process()
    except Exception as e:
        print("lte_bot: непредвиденная ошибка (%s)" % e)
