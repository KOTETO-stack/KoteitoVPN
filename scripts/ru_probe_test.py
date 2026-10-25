"""Пробный запуск: проверяет несколько серверов из подписки TCP-проверкой
с российских узлов check-host.net и присылает итог в Telegram.
Ничего в репозитории не меняет."""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "output")
API = "https://check-host.net"
HEADERS = {"Accept": "application/json", "User-Agent": "KoteitoVPN-probe/1.0"}
MAX_SERVERS = 12       # сколько серверов проверяем в пробном запуске
MAX_NODES = 3          # сколько российских узлов используем
POLL_SECONDS = 30      # сколько ждём результат одной проверки


def telegram(text):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("TELEGRAM_CHAT_ID")
    print(text)
    if not token or not chat:
        return
    body = json.dumps({"chat_id": chat, "text": text[:3500]}).encode()
    req = urllib.request.Request(
        "https://api.telegram.org/bot%s/sendMessage" % token,
        data=body, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=30).read()
    except Exception as e:
        print("Telegram: ошибка", e)


def get_json(url, timeout=30):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def russian_nodes():
    data = get_json(API + "/nodes/hosts")
    nodes = data.get("nodes", data)
    names = []
    for name, info in nodes.items():
        loc = info.get("location") if isinstance(info, dict) else None
        if loc and str(loc[0]).lower() == "ru":
            names.append(name)
    return names


def targets():
    path = os.path.join(OUT, "subscription_readable.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if "://" in l]
    except Exception:
        return []
    found = []
    for line in lines:
        try:
            u = urllib.parse.urlparse(line)
            if u.scheme.lower() not in ("vless", "trojan"):
                continue
            if not u.hostname or not u.port:
                continue
            found.append((urllib.parse.unquote(u.fragment) or u.hostname, u.hostname, u.port))
        except Exception:
            continue
    if len(found) <= MAX_SERVERS:
        return found
    step = len(found) / float(MAX_SERVERS)
    return [found[int(i * step)] for i in range(MAX_SERVERS)]


def probe(host, port, nodes):
    query = "host=%s&%s" % (urllib.parse.quote("%s:%s" % (host, port)),
                            "&".join("node=" + n for n in nodes))
    resp = get_json(API + "/check-tcp?" + query)
    rid = resp.get("request_id")
    if not rid:
        raise RuntimeError("нет request_id: " + str(resp)[:100])
    deadline = time.time() + POLL_SECONDS
    result = {}
    while time.time() < deadline:
        time.sleep(3)
        result = get_json(API + "/check-result/" + rid)
        if result and all(v is not None for v in result.values()):
            break
    ok = 0
    for v in result.values():
        if isinstance(v, list) and v and isinstance(v[0], dict) and "time" in v[0]:
            ok += 1
    return ok, len(nodes)


def main():
    try:
        nodes = russian_nodes()
    except Exception as e:
        telegram("🧪 Проверка из РФ: не удалось получить список узлов: %s" % e)
        return
    if not nodes:
        telegram("🧪 Проверка из РФ: российских узлов в check-host.net сейчас нет")
        return
    nodes = nodes[:MAX_NODES]
    items = targets()
    if not items:
        telegram("🧪 Проверка из РФ: в подписке нет vless/trojan для проверки")
        return

    lines = ["🧪 Проверка из РФ (узлов: %d, серверов: %d)" % (len(nodes), len(items))]
    good = 0
    for name, host, port in items:
        try:
            ok, total = probe(host, port, nodes)
            mark = "✔" if ok * 2 >= total else "✖"
            if mark == "✔":
                good += 1
            lines.append("%s %d/%d  %s" % (mark, ok, total, name))
        except Exception as e:
            lines.append("? %s: %s" % (name, str(e)[:60]))
        time.sleep(2)
    lines.insert(1, "Доступно из РФ: %d из %d" % (good, len(items)))
    telegram("\n".join(lines))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        telegram("🧪 Проверка из РФ: ошибка %s" % e)
