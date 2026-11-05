#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update_info.py
Собирает в одном месте то, что система знает о блокировках, и держит README.md в актуальном виде.
Запускается в workflow сразу после build_subscription.py. Подписки не трогает; любая ошибка
здесь только пропускает обновление (сборку не ломает).

Что пишет:
 1. output/censorship_info.json  одна сводка: списки РКН, приоритет стран, OONI по операторам,
    расписание workflow и текущие лимиты сборки.
 2. data/rkn_seen.json  память о серверах из нашего пула, чьи IP попали в списки РКН:
    IP -> когда впервые и когда последний раз замечен, сеть, страна. Хранится
    RKN_SEEN_DAYS дней, не больше RKN_SEEN_MAX записей. Полные списки РКН не коммитятся:
    они большие и скачиваются заново (кэш .cache/signals).
 3. README.md  блок между строками <!-- AUTO-INFO:BEGIN --> и <!-- AUTO-INFO:END -->.
    Всё вне блока скрипт не трогает. Если маркеров нет, блок добавляется в конец файла.
    В блоке: как система работает сейчас (расписания из .github/workflows и лимиты из
    build_subscription.py), сводка по спискам РКН, таблица приоритета стран, давление
    блокировок по операторам (OONI).
"""
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

README = os.path.join(ROOT, "README.md")
INFO_JSON = os.path.join(ROOT, "output", "censorship_info.json")
SEEN_FILE = os.path.join(ROOT, "data", "rkn_seen.json")
COUNTRY_FILE = os.path.join(ROOT, "output", "country_priority.json")
OONI_FILE = os.path.join(ROOT, "output", "ooni_censorship_index.json")
ASN_FILE = os.path.join(ROOT, "output", "asn_info.json")
CONFIGS_FILE = os.path.join(ROOT, "masked_configs.json")
WORKFLOWS_DIR = os.path.join(ROOT, ".github", "workflows")

BEGIN = "<!-- AUTO-INFO:BEGIN -->"
END = "<!-- AUTO-INFO:END -->"
RKN_SEEN_DAYS = 30
RKN_SEEN_MAX = 3000
TOP_NETS = 8                  # сколько сетей показывать у серверов из списков РКН


def read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, type(default)) else default
    except (OSError, ValueError):
        return default


def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def country_name(code):
    try:
        from geo_flag import COUNTRY_RU
        return COUNTRY_RU.get(code, code)
    except Exception:
        return code


# ---------- расписания workflow ----------
def describe_cron(expr):
    parts = expr.split()
    if len(parts) != 5:
        return expr
    m, h, dom, mon, dow = parts
    if dom == "*" and mon == "*" and dow == "*":
        if h == "*" and m.isdigit():
            return "каждый час в :%02d" % int(m)
        if h.startswith("*/") and h[2:].isdigit() and m.isdigit():
            return "каждые %s ч (в :%02d)" % (h[2:], int(m))
        if m.startswith("*/") and m[2:].isdigit() and h == "*":
            return "каждые %s мин" % m[2:]
        if h.isdigit() and m.isdigit():
            return "ежедневно в %02d:%02d UTC" % (int(h), int(m))
    return expr


def workflow_schedules():
    out = []
    try:
        names = sorted(n for n in os.listdir(WORKFLOWS_DIR) if n.endswith((".yml", ".yaml")))
    except OSError:
        return out
    for fname in names:
        try:
            with open(os.path.join(WORKFLOWS_DIR, fname), "r", encoding="utf-8") as f:
                text = f.read()
        except OSError:
            continue
        m = re.search(r"^name:\s*(.+?)\s*$", text, re.M)
        crons = re.findall(r"cron:\s*[\"']([^\"']+)[\"']", text)
        out.append({
            "file": fname,
            "name": (m.group(1).strip("\"'") if m else fname),
            "schedule": [describe_cron(c) for c in crons],
            "manual": "workflow_dispatch" in text,
        })
    return out


def build_limits():
    """Текущие лимиты сборки прямо из build_subscription.py и net_signals.py."""
    limits = {}
    try:
        import build_subscription as bs
        for key in ("SUBSCRIPTION_COUNT", "MAX_SERVERS", "MAX_PER_COUNTRY", "MOBILE_QUOTA",
                    "PROBE_PENALTY_MS", "SHRINK_GUARD", "SIGNALS_ENABLED"):
            if hasattr(bs, key):
                limits[key] = getattr(bs, key)
    except Exception:
        pass
    try:
        import net_signals as ns
        for key in ("RKN_PENALTY_MS", "RKN_SOFT_PENALTY_MS", "RKN_MAX_SHARE", "COUNTRY_BONUS_MAX_MS",
                    "LTE_SERVER_GREEN_BONUS_MS", "LTE_SERVER_RED_PENALTY_MS", "LTE_ASN_MAX_MS"):
            if hasattr(ns, key):
                limits[key] = getattr(ns, key)
    except Exception:
        pass
    return limits


# ---------- списки РКН ----------
def rkn_info():
    """Сводка по спискам РКН и серверам пула, попавшим в них."""
    info = {"available": False, "sources": {}, "ranges": 0, "addresses": 0,
            "pool_total": 0, "pool_flagged": 0, "flagged": []}
    try:
        import net_signals as ns
    except Exception as e:
        info["error"] = "net_signals не загрузился: %s" % e
        return info
    rkn, per_source = ns.load_rkn()
    for name, _url in ns.RKN_SOURCES:
        path = os.path.join(ns.CACHE_DIR, name + ".lst")
        if os.path.exists(path):
            info["sources"][name] = {
                "entries": per_source.get(name, 0),
                "file_updated_utc": datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
                                    .strftime("%Y-%m-%d %H:%M"),
            }
    info["ranges"] = rkn.count
    info["addresses"] = sum(e - s + 1 for s, e in zip(rkn.starts, rkn.ends))
    info["available"] = rkn.count > 0

    configs = read_json(CONFIGS_FILE, [])
    asn_info = read_json(ASN_FILE, {})
    info["pool_total"] = len(configs)
    if rkn.count == 0:
        return info
    seen_ips = set()
    for c in configs:
        host = str(c.get("host", "")).strip().lower()
        a = asn_info.get(host) or {}
        ip = str(c.get("net_ip") or a.get("ip") or "").strip()
        if not ip or ip in seen_ips or not rkn.contains(ip):
            continue
        seen_ips.add(ip)
        info["flagged"].append({
            "ip": ip,
            "host": host,
            "port": c.get("port"),
            "country": c.get("country_code") or "??",
            "asn": str(c.get("net_asn") or a.get("asn") or ""),
            "net_name": str(c.get("net_name") or a.get("name") or ""),
        })
    info["pool_flagged"] = len(info["flagged"])
    return info


def update_seen(flagged, today):
    """Память о заблокированных адресах: IP -> первая и последняя дата."""
    seen = read_json(SEEN_FILE, {})
    for f in flagged:
        rec = seen.get(f["ip"]) or {"first": today}
        rec.update({"last": today, "country": f["country"], "asn": f["asn"], "net": f["net_name"]})
        seen[f["ip"]] = rec
    cutoff = datetime.fromtimestamp(time.time() - RKN_SEEN_DAYS * 86400, timezone.utc).strftime("%Y-%m-%d")
    seen = {ip: r for ip, r in seen.items() if r.get("last", "") >= cutoff}
    if len(seen) > RKN_SEEN_MAX:
        keep = sorted(seen, key=lambda ip: seen[ip].get("last", ""), reverse=True)[:RKN_SEEN_MAX]
        seen = {ip: seen[ip] for ip in keep}
    seen = dict(sorted(seen.items()))
    write_json(SEEN_FILE, seen)
    return seen


# ---------- разметка ----------
def md_escape(text):
    return str(text).replace("|", "/").replace("\n", " ")


def build_block(info, now_str):
    L = [BEGIN, "", "## Актуальные данные (обновляется автоматически)", "",
         "Обновлено: %s UTC. Этот блок пишет `scripts/update_info.py` после каждой сборки подписок, "
         "вручную его править не нужно (всё вне блока скрипт не трогает)." % now_str, ""]

    lim = info["limits"]
    L += ["### Как система работает сейчас", ""]
    if "SUBSCRIPTION_COUNT" in lim:
        L.append("- Подписок: %s, в каждой до %s серверов, не больше %s серверов одной страны; "
                 "мобильная добавка до %s серверов на подписку."
                 % (lim.get("SUBSCRIPTION_COUNT"), lim.get("MAX_SERVERS"),
                    lim.get("MAX_PER_COUNTRY"), lim.get("MOBILE_QUOTA")))
    L.append("")
    L += ["| Workflow | Расписание | Вручную |", "|---|---|---|"]
    for w in info["workflows"]:
        sched = ", ".join(w["schedule"]) if w["schedule"] else "нет"
        L.append("| %s (`%s`) | %s | %s |" % (md_escape(w["name"]), w["file"], sched,
                                              "да" if w["manual"] else "нет"))
    L.append("")

    r = info["rkn"]
    L += ["### Заблокированные РКН адреса", ""]
    if r.get("available"):
        for name, s in r["sources"].items():
            L.append("- Список `%s`: записей %d, файл обновлён %s UTC." % (name, s["entries"], s["file_updated_utc"]))
        L.append("- После слияния диапазонов: %d, они покрывают адресов: %d." % (r["ranges"], r["addresses"]))
        share = round(100.0 * r["pool_flagged"] / r["pool_total"]) if r["pool_total"] else 0
        L.append("- Серверов пула в списках сейчас: %d из %d (%d%%). Такие серверы получают штраф при сортировке "
                 "и в мобильную добавку не берутся." % (r["pool_flagged"], r["pool_total"], share))
        L.append("- Замечено адресов за последние %d дней: %d (память в `data/rkn_seen.json`)."
                 % (RKN_SEEN_DAYS, info["rkn_seen_count"]))
        nets = Counter((f["asn"] or "?", f["net_name"]) for f in r["flagged"])
        if nets:
            L += ["", "Сети серверов из списков РКН:", "", "| Сеть | Название | Серверов |", "|---|---|---|"]
            for (asn, name), n in nets.most_common(TOP_NETS):
                L.append("| %s | %s | %d |" % (asn, md_escape(name) or "-", n))
    else:
        L.append("Списки РКН сейчас недоступны (не скачались и в кэше пусто); штраф за РКН не применяется. %s"
                 % r.get("error", ""))
    L.append("")

    L += ["### Приоритет стран", ""]
    countries = info["country_priority"].get("countries", {})
    ranked = sorted(((cc, v) for cc, v in countries.items() if v.get("quality") is not None),
                    key=lambda kv: -kv[1].get("bonus_ms", 0))
    if ranked:
        L += ["Считается из данных, не вручную: ответ российских узлов, доля серверов в списках РКН и в сетях "
              "ТСПУ. Бонус плюсом ускоряет страну в сортировке, минус замедляет.", "",
              "| Страна | Бонус, мс | Качество | Серверов | Проверено из РФ | В списках РКН | В сетях ТСПУ |",
              "|---|---|---|---|---|---|---|"]
        for cc, v in ranked:
            L.append("| %s | %+.1f | %.2f | %d | %d | %d%% | %d%% |" % (
                country_name(cc), v.get("bonus_ms", 0), v.get("quality", 0), v.get("servers", 0),
                v.get("probed", 0), round(100 * v.get("rkn_share", 0)), round(100 * v.get("tspu_share", 0))))
    else:
        L.append("Данных пока мало, бонусов нет.")
    L.append("")

    o = info["ooni"]
    L += ["### OONI: давление блокировок по операторам", ""]
    if o:
        if o.get("pressure_percent") is not None:
            L.append("Общий индикатор по России: %s%% (измерений: %s, период с %s по %s)."
                     % (o.get("pressure_percent"), o.get("measurements", "?"), o.get("since", "?"), o.get("until", "?")))
            L.append("")
        ops = o.get("operators") or []
        if ops:
            L += ["| Сеть | Оператор | Давление блокировок | Измерений |", "|---|---|---|---|"]
            for op in ops:
                L.append("| %s | %s | %s%% | %s |" % (op.get("asn", "?"), md_escape(op.get("name") or "-"),
                                                      op.get("pressure", "?"), op.get("measurements", "?")))
            L.append("")
        types = o.get("blocking_types") or {}
        if types:
            L.append("Способы блокировок (как вернул OONI): " + ", ".join("%s %s" % (k, v) for k, v in types.items()) + ".")
            L.append("")
    else:
        L += ["Данных OONI пока нет.", ""]
    L += [END]
    return "\n".join(L)


def update_readme(block):
    try:
        with open(README, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        text = "# KoteitoVPN\n"
    if BEGIN in text and END in text and text.index(BEGIN) < text.index(END):
        pre, rest = text.split(BEGIN, 1)
        _old, post = rest.split(END, 1)
        new = pre + block + post
    else:
        new = text.rstrip("\n") + "\n\n" + block + "\n"
    if new == text:
        print("README.md: без изменений")
        return
    with open(README, "w", encoding="utf-8") as f:
        f.write(new)
    print("README.md: блок обновлён")


def main():
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    info = {
        "updated_utc": now.strftime("%Y-%m-%dT%H:%M:%S"),
        "limits": build_limits(),
        "workflows": workflow_schedules(),
        "rkn": rkn_info(),
        "country_priority": read_json(COUNTRY_FILE, {}),
        "ooni": read_json(OONI_FILE, {}),
    }
    seen = {}
    if info["rkn"].get("available"):
        seen = update_seen(info["rkn"]["flagged"], today)
    else:
        seen = read_json(SEEN_FILE, {})
    info["rkn_seen_count"] = len(seen)
    write_json(INFO_JSON, info)
    print("Сводка записана: output/censorship_info.json (РКН в пуле: %d из %d, замечено за %d дн.: %d)"
          % (info["rkn"].get("pool_flagged", 0), info["rkn"].get("pool_total", 0), RKN_SEEN_DAYS, len(seen)))
    update_readme(build_block(info, now.strftime("%Y-%m-%d %H:%M")))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("update_info: ошибка (%s), обновление пропущено." % e)
