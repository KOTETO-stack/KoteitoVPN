#!/usr/bin/env python3
"""LTE Learn: что отличает зелёные серверы от красных по нашим замерам.

Только читает lte_results.txt и печатает отчёт в лог, плюс пишет data/lte_learn.json.
Ничего в подписках и других скриптах не меняет.

Берутся только строки с датой (2026-11-03 13:05;G;host:port;описание;мс).
Один сервер за один день считается один раз (последний замер дня),
чтобы частые перемеры одного сервера не искажали доли.
"""
import json
import os
import re
from collections import defaultdict

SRC = "lte_results.txt"
OUT = "data/lte_learn.json"
RECENT_DAYS = 5      # «недавние» = последние N дней, в которых были замеры
MIN_N = 4            # значения признака с меньшим числом замеров не показываем
PRIOR = 3.0          # сила сглаживания: малые выборки тянутся к общей доле зелёных
TS = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2});")
PROTOS = ("vless", "vmess", "trojan", "hysteria2", "hy2")


def parse(path):
    rows = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            m = TS.match(line)
            if not m:
                continue
            parts = line.split(";", 4)
            if len(parts) < 3:
                continue
            gr = parts[1].strip().upper()
            addr = parts[2].strip()
            if gr not in ("G", "R") or ":" not in addr:
                continue
            desc = parts[3] if len(parts) > 3 else ""
            day = m.group(1)
            rows[(day, addr)] = {"day": day, "hour": int(m.group(2)),
                                 "ok": gr == "G", "addr": addr, "desc": desc}
    return list(rows.values())


def features(r):
    host, port = r["addr"].rsplit(":", 1)
    base, _, extra = r["desc"].partition(" | ")
    kv = {}
    for tok in extra.replace(";", " ").split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            kv[k] = v
    low = base.lower()
    proto = next((p for p in PROTOS if p in low), "?")
    if proto == "hy2":
        proto = "hysteria2"
    f = {"протокол": proto, "порт": port}
    is_ip = re.match(r"^\d+\.\d+\.\d+\.\d+$", host) is not None
    f["адрес"] = "IP" if is_ip else "домен"
    if is_ip:
        f["сеть /16"] = ".".join(host.split(".")[:2]) + ".x.x"
    else:
        f["семья домена"] = ".".join(host.split(".")[-2:])
    toks = base.split()
    if toks and toks[0].lower() not in PROTOS and toks[0].lower() not in ("reality", "tls", "ws"):
        f["страна"] = toks[0]
    for key, name in (("sec", "защита"), ("tr", "транспорт"), ("fp", "отпечаток"), ("flow", "flow")):
        if key in kv:
            f[name] = kv[key]
    sni = kv.get("sni", "")
    if sni and sni != host:
        f["семья SNI"] = ".".join(sni.split(".")[-2:])
    f["время"] = "ночь" if (r["hour"] >= 23 or r["hour"] < 7) else "день"
    return f


def smooth(g, n, p0):
    return (g + PRIOR * p0) / (n + PRIOR)


def main():
    if not os.path.exists(SRC):
        print(f"Нет файла {SRC}")
        return
    rows = parse(SRC)
    if not rows:
        print("Нет строк с датой")
        return
    days = sorted({r["day"] for r in rows})
    recent = set(days[-RECENT_DAYS:])
    total_g = sum(r["ok"] for r in rows)
    p0 = total_g / len(rows)
    print(f"Замеров (сервер-день): {len(rows)}, зелёных {total_g} ({p0:.0%}); дней {len(days)}: {days[0]} .. {days[-1]}")

    print("\n== По дням ==")
    by_day = defaultdict(lambda: [0, 0])
    for r in rows:
        by_day[r["day"]][0] += 1
        by_day[r["day"]][1] += r["ok"]
    for d in days:
        n, g = by_day[d]
        print(f"{d}: {g} из {n} ({g / n:.0%})")
    last3 = days[-3:]
    n3 = sum(by_day[d][0] for d in last3)
    g3 = sum(by_day[d][1] for d in last3)
    prev = days[:-3]
    np_ = sum(by_day[d][0] for d in prev)
    gp = sum(by_day[d][1] for d in prev)
    r3 = g3 / n3 if n3 else 0
    rp = gp / np_ if np_ else 0
    crisis = bool(n3 >= 10 and r3 < 0.10)
    print(f"Последние 3 дня: {r3:.0%} ({g3}/{n3}); раньше: {rp:.0%} ({gp}/{np_}); режим «почти всё закрыто»: {'ДА' if crisis else 'нет'}")

    stat = defaultdict(lambda: {"n": 0, "g": 0, "nr": 0, "gr": 0})
    for r in rows:
        for k, v in features(r).items():
            s = stat[(k, v)]
            s["n"] += 1
            s["g"] += r["ok"]
            if r["day"] in recent:
                s["nr"] += 1
                s["gr"] += r["ok"]

    print(f"\n== Признаки (от {MIN_N} замеров). всё время / последние {RECENT_DAYS} дн. ==")
    by_feat = defaultdict(list)
    for (k, v), s in stat.items():
        if s["n"] >= MIN_N:
            by_feat[k].append((v, s))
    feat_json = {}
    for k in sorted(by_feat):
        print(f"\n[{k}]")
        feat_json[k] = {}
        for v, s in sorted(by_feat[k], key=lambda x: -x[1]["n"])[:12]:
            sm = smooth(s["g"], s["n"], p0)
            rec = f"{s['gr']}/{s['nr']}" if s["nr"] else "-"
            print(f"  {v}: {s['g']}/{s['n']} ({s['g'] / s['n']:.0%}, сглаж. {sm:.0%}); недавно {rec}")
            feat_json[k][v] = {**s, "smooth": round(sm, 3)}

    per = defaultdict(list)
    for r in rows:
        if r["day"] in recent:
            per[r["addr"]].append((r["day"], r["ok"], r["desc"].partition(" | ")[0]))
    print(f"\n== Зелёные за последние {RECENT_DAYS} дн. ==")
    greens = []
    for addr, lst in sorted(per.items()):
        gs = sum(1 for _, ok, _ in lst if ok)
        if gs:
            tag = "стабильный" if gs == len(lst) and gs >= 2 else ("мигает" if gs < len(lst) else "один замер")
            greens.append({"addr": addr, "green": gs, "total": len(lst), "tag": tag})
            print(f"  {addr}: {gs}/{len(lst)} {tag}; {lst[-1][2]}")
    if not greens:
        print("  нет")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump({"days": {d: by_day[d] for d in days}, "p0": round(p0, 3), "crisis": crisis,
                   "features": feat_json, "recent_greens": greens}, fh, ensure_ascii=False, indent=1)
    print(f"\nСохранено: {OUT}")


if __name__ == "__main__":
    main()
