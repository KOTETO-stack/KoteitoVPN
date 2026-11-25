#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
explore.py
Экспериментальные слоты в подписках. Вызывается из build_subscription.py (одна вставка в main()).

Зачем: пока на LTE почти всё закрыто, ранжировать нечего. Нужно выяснить, есть ли вообще живой класс
серверов. Поэтому наверх КАЖДОЙ подписки ставится набор из EXPLORE_TOTAL серверов, выбранных не по
рейтингу, а для разнообразия (протокол, защита, транспорт, страна, сеть), плюс контрольные серверы.
Их можно замерить за одну сессию и получить чистое сравнение классов.

Как выбираются:
 - класс = (протокол, защита, транспорт), например (vless, tls, ws);
 - в каждом классе квота CLASS_BASE_QUOTA; если в классе был зелёный сервер за последние GREEN_DAYS
   дней (lte_results.txt), квота больше на CLASS_GREEN_BONUS;
 - внутри класса берётся самый «новый» сервер: другая страна и сеть, чем у уже выбранных;
 - серверы, замеренные за последние SKIP_DAYS дней, не берутся (замеренный уходит, на его место
   приходит новый, так набор обновляется сам);
 - набор держится между сборками (output/explore_state.json), пока сервер не замерят;
 - контрольные серверы (CONTROLS) идут всегда, если они есть в пуле.

Серверы ставятся в начало каждой подписки, а подписка обрезается с конца до MAX_SERVERS.
Список для замера пишется в output/subscription_explore_list.txt.
Любая ошибка не ломает сборку. EXPLORE_ENABLED = False выключает всё.
"""
import json
import os
import re
import urllib.parse
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LTE_FILE = os.path.join(ROOT, "lte_results.txt")
OUT_DIR = os.path.join(ROOT, "output")
STATE_FILE = os.path.join(OUT_DIR, "explore_state.json")
LIST_FILE = os.path.join(OUT_DIR, "subscription_explore_list.txt")

EXPLORE_ENABLED = True
EXPLORE_TOTAL = 16            # сколько экспериментальных серверов (без контрольных)
CLASS_BASE_QUOTA = 2          # сколько серверов брать из каждого класса
CLASS_GREEN_BONUS = 2         # добавка к квоте класса, где недавно был зелёный
GREEN_DAYS = 5                # «недавно» для зелёного
SKIP_DAYS = 3                 # замеренные за последние N дней не берём
CONTROLS = ["31.76.3.52:443", "5.182.87.242:443"]   # контрольные: недавние зелёные

TS = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2});")
NUM_RE = re.compile(r"\s*-\s*\d+\s*$")
IP_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def info(raw):
    """Признаки сервера по ссылке или None, если адрес или порт не читаются."""
    try:
        u = urllib.parse.urlparse(raw)
        host = (u.hostname or "").lower()
        port = u.port
    except ValueError:
        return None
    if not host or port is None:
        return None
    scheme = (u.scheme or "").lower()
    if scheme == "hy2":
        scheme = "hysteria2"
    q = {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)}
    if scheme == "hysteria2":
        sec, tr = "tls", "udp"
    else:
        sec = (q.get("security") or ("tls" if scheme == "trojan" else "none")).lower()
        tr = (q.get("type") or "tcp").lower()
    if IP_RE.match(host):
        net, fam = ".".join(host.split(".")[:2]), ""
    else:
        net, fam = "", ".".join(host.split(".")[-2:])
    return {"addr": "%s:%d" % (host, port), "cls": (scheme, sec, tr), "net": net, "fam": fam}


def load_lte():
    """addr -> список (дата, зелёный?) по строкам lte_results.txt с датой."""
    res = {}
    if not os.path.exists(LTE_FILE):
        return res
    with open(LTE_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            m = TS.match(line)
            if not m:
                continue
            parts = line.split(";", 4)
            if len(parts) < 3 or parts[1].strip().upper() not in ("G", "R"):
                continue
            try:
                d = datetime.strptime(m.group(1), "%Y-%m-%d").date()
            except ValueError:
                continue
            res.setdefault(parts[2].strip().lower(), []).append((d, parts[1].strip().upper() == "G"))
    return res


def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [b for b in data.get("chosen", []) if isinstance(b, str)]
    except (OSError, ValueError, AttributeError):
        return []


def clean_name(name):
    cleaned = NUM_RE.sub("", name or "").strip()
    return cleaned or (name or "VPN")


def apply(groups, configs, max_servers):
    """Ставит экспериментальные серверы в начало каждой подписки. Возвращает новые группы."""
    if not EXPLORE_ENABLED or not groups:
        return groups
    today = datetime.now(timezone(timedelta(hours=3))).date()
    lte = load_lte()

    meta = {}
    for c in configs:
        raw = c.get("raw", "")
        base = raw.split("#", 1)[0]
        inf = info(raw)
        if base and inf:
            inf["country"] = c.get("country_code", "??")
            meta[base] = (c, inf)

    def measured(addr, days):
        return any((today - d).days <= days for d, _ in lte.get(addr, []))

    def green_recent(addr):
        return any(ok and (today - d).days <= GREEN_DAYS for d, ok in lte.get(addr, []))

    quota = {}
    for _, inf in meta.values():
        cls = inf["cls"]
        quota.setdefault(cls, CLASS_BASE_QUOTA)
        if green_recent(inf["addr"]):
            quota[cls] = CLASS_BASE_QUOTA + CLASS_GREEN_BONUS

    controls = [b for b, (_, inf) in meta.items() if inf["addr"] in CONTROLS]
    chosen = []
    cnt_cls, cnt_country, cnt_net, cnt_fam = {}, {}, {}, {}

    def take(b):
        inf = meta[b][1]
        chosen.append(b)
        cnt_cls[inf["cls"]] = cnt_cls.get(inf["cls"], 0) + 1
        cnt_country[inf["country"]] = cnt_country.get(inf["country"], 0) + 1
        if inf["net"]:
            cnt_net[inf["net"]] = cnt_net.get(inf["net"], 0) + 1
        if inf["fam"]:
            cnt_fam[inf["fam"]] = cnt_fam.get(inf["fam"], 0) + 1

    def usable(b):
        inf = meta[b][1]
        return inf["addr"] not in CONTROLS and not measured(inf["addr"], SKIP_DAYS)

    kept = 0
    for b in load_state():
        if b in meta and b not in chosen and usable(b) and len(chosen) < EXPLORE_TOTAL \
                and cnt_cls.get(meta[b][1]["cls"], 0) < quota[meta[b][1]["cls"]]:
            take(b)
            kept += 1

    def score(b):
        inf = meta[b][1]
        pen = 2 * cnt_country.get(inf["country"], 0)
        pen += 3 * cnt_net.get(inf["net"], 0) if inf["net"] else 0
        pen += 3 * cnt_fam.get(inf["fam"], 0) if inf["fam"] else 0
        return (pen, meta[b][0].get("ping_ms", 9999), b)

    classes = sorted(quota, key=lambda k: (-quota[k], k))
    progress = True
    while len(chosen) < EXPLORE_TOTAL and progress:
        progress = False
        for cls in classes:
            if len(chosen) >= EXPLORE_TOTAL:
                break
            if cnt_cls.get(cls, 0) >= quota[cls]:
                continue
            cands = [b for b in meta if meta[b][1]["cls"] == cls and b not in chosen and usable(b)]
            if not cands:
                continue
            take(min(cands, key=score))
            progress = True

    ordered = controls + chosen
    items = []
    for b in ordered:
        item = dict(meta[b][0])
        item["explore"] = True
        items.append(item)
    ex_bases = set(ordered)

    new_groups = []
    for g in groups:
        rest = [c for c in g if c.get("raw", "").split("#", 1)[0] not in ex_bases]
        new_groups.append((items + rest)[:max_servers])

    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"chosen": chosen}, f, ensure_ascii=False)
        lines = ["# Экспериментальные серверы (наверху каждой подписки). Замерь на LTE за одну сессию,",
                 "# пришли боту и зелёные, и красные. Замеренные уйдут, на их место придут новые.",
                 "# Формат: роль | адрес | класс (протокол, защита, транспорт) | страна | название"]
        for b in ordered:
            c, inf = meta[b]
            role = "контроль" if b in controls else "новый"
            lines.append("%s | %s | %s | %s | %s" % (
                role, inf["addr"], ",".join(inf["cls"]), inf["country"],
                clean_name(c.get("display_name") or c.get("remark") or "VPN")))
        with open(LIST_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        print("Эксперимент: файлы состояния и списка не записаны: %s" % e)

    by_cls = {}
    for b in chosen:
        by_cls[",".join(meta[b][1]["cls"])] = by_cls.get(",".join(meta[b][1]["cls"]), 0) + 1
    print("Эксперимент: контрольных %d, новых %d (из прошлой сборки сохранено %d), классов в пуле %d."
          % (len(controls), len(chosen), kept, len(quota)))
    print("Эксперимент по классам: " + "; ".join("%s: %d" % kv for kv in sorted(by_cls.items())))
    return new_groups
