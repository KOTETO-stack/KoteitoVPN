"""Проверка серверов с российских узлов check-host.net (TCP, vless/trojan).
Каждый запуск проверяет порцию серверов, которых не проверяли дольше всего,
и дописывает результат в output/ru_probe.json. Подписку он не меняет:
файл читает build_subscription.py."""
import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "output")
PROBE_FILE = os.path.join(OUT, "ru_probe.json")
API = "https://check-host.net"
HEADERS = {"Accept": "application/json", "User-Agent": "KoteitoVPN-probe/1.0"}

BATCH = int(os.environ.get("PROBE_BATCH", "40"))   # серверов за один запуск
MAX_NODES = 3                                       # российских узлов на проверку
POLL_SECONDS = 30                                   # ждём результат одной проверки
REFRESH_HOURS = 24                                  # после этого проверка считается устаревшей
KEEP_HOURS = 72                                     # старше этого записи удаляются


class RateLimited(Exception):
    pass


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
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited()
        raise


def read_links(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read().strip()
    except Exception:
        return []
    if "://" not in text:
        try:
            text = base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "ignore")
        except Exception:
            return []
    return [l.strip() for l in text.splitlines() if "://" in l]


def key_of(line):
    """(host:port, имя) для vless/trojan, иначе None."""
    try:
        u = urllib.parse.urlparse(line)
        if u.scheme.lower() not in ("vless", "trojan"):
            return None
        if not u.hostname or not u.port:
            return None
        name = urllib.parse.unquote(u.fragment) or u.hostname
        return "%s:%d" % (u.hostname.lower(), u.port), name
    except Exception:
        return None


def candidates():
    names, prio = {}, {}
    for fname in ("subscription_readable.txt", "subscription_cellular_readable.txt"):
        for line in read_links(os.path.join(OUT, fname)):
            r = key_of(line)
            if r:
                names.setdefault(r[0], r[1])
                prio[r[0]] = 0
    for line in read_links(os.path.join(OUT, "raw_servers.txt")):
        r = key_of(line)
        if r:
            names.setdefault(r[0], r[1])
            prio.setdefault(r[0], 1)
    return names, prio


def load_data():
    try:
        with open(PROBE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_data(data):
    os.makedirs(OUT, exist_ok=True)
    tmp = PROBE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=0, sort_keys=True)
    os.replace(tmp, PROBE_FILE)


def russian_nodes():
    data = get_json(API + "/nodes/hosts")
    nodes = data.get("nodes", data)
    names = []
    for name, info in nodes.items():
        loc = info.get("location") if isinstance(info, dict) else None
        if loc and str(loc[0]).lower() == "ru":
            names.append(name)
    return sorted(names)[:MAX_NODES]


def probe(host, port, nodes):
    """Возвращает (ok, total) по завершившимся узлам или None."""
    query = "host=%s&%s" % (urllib.parse.quote("%s:%s" % (host, port)),
                            "&".join("node=" + n for n in nodes))
    resp = get_json(API + "/check-tcp?" + query)
    rid = resp.get("request_id")
    if not rid:
        raise RuntimeError("нет request_id")
    deadline = time.time() + POLL_SECONDS
    result = {}
    while time.time() < deadline:
        time.sleep(3)
        result = get_json(API + "/check-result/" + rid)
        if result and all(v is not None for v in result.values()):
            break
    ok = total = 0
    for v in result.values():
        if v is None:
            continue
        total += 1
        if isinstance(v, list) and v and isinstance(v[0], dict) and "time" in v[0]:
            ok += 1
    return (ok, total) if total else None


def main():
    names, prio = candidates()
    if not names:
        print("Нет vless/trojan для проверки")
        return
    now = time.time()
    data = load_data()
    data = {k: v for k, v in data.items()
            if k in names and now - float(v.get("t", 0)) < KEEP_HOURS * 3600}

    def order_key(k):
        t = float(data.get(k, {}).get("t", 0))
        stale = (now - t) > REFRESH_HOURS * 3600
        return (0 if stale else 1, prio[k], t)

    batch = sorted(names, key=order_key)[:BATCH]
    try:
        nodes = russian_nodes()
    except Exception as e:
        telegram("🧪 Проверка из РФ: не удалось получить узлы: %s" % e)
        return
    if not nodes:
        telegram("🧪 Проверка из РФ: российских узлов сейчас нет")
        return

    checked = []
    for k in batch:
        host, port = k.rsplit(":", 1)
        res = None
        try:
            try:
                res = probe(host, port, nodes)
            except RateLimited:
                print("429, пауза 30 с")
                time.sleep(30)
                res = probe(host, port, nodes)
        except RateLimited:
            print("Снова 429, останавливаемся, прогресс сохраняем")
            break
        except Exception as e:
            print("Ошибка %s: %s" % (k, e))
            continue
        if res is None:
            continue
        data[k] = {"ok": res[0], "total": res[1], "t": int(time.time())}
        checked.append(k)
        time.sleep(2)

    save_data(data)
    bad = [k for k in checked if data[k]["ok"] == 0]
    print("Проверено: %d, недоступно из РФ: %d, в файле записей: %d"
          % (len(checked), len(bad), len(data)))

    if os.environ.get("ALWAYS_REPORT", "").lower() == "true":
        lines = ["🧪 Проверка из РФ: проверено %d, недоступно %d, всего в файле %d"
                 % (len(checked), len(bad), len(data))]
        lines += ["✖ " + names[k] for k in bad[:15]]
        telegram("\n".join(lines))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Проверка из РФ: непредвиденная ошибка (%s)" % e)
