#!/usr/bin/env python3
# scripts/lte_insights.py
# Разбор замеров LTE: сессии, один IP с разными портами, семьи сетей,
# мигающие серверы и кандидаты в контрольные. Только читает файлы, ничего не меняет.
import os
import re
from collections import OrderedDict
from datetime import datetime, timedelta

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FILES = [
    os.path.join(ROOT, "data", "lte_results_archive.txt"),
    os.path.join(ROOT, "lte_results.txt"),
]
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SESSION_GAP_MIN = 30      # пауза между замерами, после которой начинается новая сессия
BAD_SESSION_MAX_G = 25    # % зелёных, ниже которого сессия подозрительна
BAD_SESSION_MIN_N = 8     # минимум замеров, чтобы так судить


def parse():
    recs, seen = [], set()
    for path in FILES:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                p = [x.strip() for x in line.split(";")]
                if len(p) < 3 or p[1] not in ("G", "R"):
                    continue
                label, res, addr = p[0], p[1], p[2].lower()
                if ":" not in addr:
                    continue
                key = (label, res, addr)
                if key in seen:
                    continue
                seen.add(key)
                host, port = addr.rsplit(":", 1)
                t = datetime.strptime(label, "%Y-%m-%d %H:%M") if TS_RE.match(label) else None
                recs.append({
                    "label": label, "t": t, "res": res, "addr": addr,
                    "host": host, "port": port,
                    "desc": p[3] if len(p) > 3 else "", "n": len(recs),
                })
    return recs


def short(text, n=34):
    return text if len(text) <= n else text[: n - 1] + "…"


def family(host):
    if IPV4_RE.match(host):
        return ".".join(host.split(".")[:3]) + ".*"
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def main():
    recs = parse()
    if not recs:
        print("Нет замеров: lte_results.txt не найден или пуст")
        return

    by_addr = OrderedDict()
    for r in recs:
        by_addr.setdefault(r["addr"], []).append(r)
    latest = {a: rs[-1] for a, rs in by_addr.items()}
    print(f"Замеров {len(recs)}, серверов {len(by_addr)}")

    # 1. Сессии
    timed = sorted([r for r in recs if r["t"]], key=lambda r: (r["t"], r["n"]))
    sessions, cur = [], []
    for r in timed:
        if cur and r["t"] - cur[-1]["t"] > timedelta(minutes=SESSION_GAP_MIN):
            sessions.append(cur)
            cur = []
        cur.append(r)
    if cur:
        sessions.append(cur)
    print("\n== Сессии замеров (последние 12, где не меньше 5 замеров) ==")
    shown = [s for s in sessions if len(s) >= 5][-12:]
    for s in shown:
        g = sum(1 for r in s if r["res"] == "G")
        pct = round(100 * g / len(s))
        flag = ""
        if len(s) >= BAD_SESSION_MIN_N and pct <= BAD_SESSION_MAX_G:
            flag = "  <- почти всё красное: возможно, плохая сеть в тот момент"
        print(f"{s[0]['t']:%d.%m %H:%M}  замеров {len(s)}, зелёных {g} ({pct}%){flag}")
    if not shown:
        print("Пока нет сессий с 5 и более замерами")

    # 2. Один IP или домен, разные порты
    groups = {}
    for a, rs in by_addr.items():
        groups.setdefault(rs[0]["host"], []).append(a)
    multi = {h: al for h, al in groups.items() if len(al) >= 2}
    print("\n== Один адрес, разные порты (последний результат; G/R за всё время) ==")
    if not multi:
        print("Пока нет адресов с двумя и более замеренными портами")
    for h, al in sorted(multi.items()):
        results = {latest[a]["res"] for a in al}
        mark = "  <- РАЗНЫЕ: причина в порту или протоколе" if len(results) > 1 else ""
        print(f"{h}{mark}")
        for a in al:
            rs = by_addr[a]
            g = sum(1 for r in rs if r["res"] == "G")
            print(f"   :{rs[0]['port']} {latest[a]['res']} (G{g}/R{len(rs) - g}) {short(latest[a]['desc'])}")

    # 3. Семьи (подсеть /24 или домен второго уровня)
    fam = {}
    for a, r in latest.items():
        fam.setdefault(family(r["host"]), []).append(r["res"])
    rows = [(k, v) for k, v in fam.items() if len(v) >= 3]
    rows.sort(key=lambda kv: -len(kv[1]))
    print("\n== Семьи с тремя и более серверами (по последнему результату) ==")
    if not rows:
        print("Пока нет семей с тремя серверами")
    for k, v in rows[:15]:
        g = v.count("G")
        print(f"{k}: зелёных {g} из {len(v)} ({round(100 * g / len(v))}%)")

    # 4. Мигающие
    flips = []
    for a, rs in by_addr.items():
        s = "".join(r["res"] for r in rs)
        if "G" in s and "R" in s:
            flips.append((a, s))
    flips.sort(key=lambda x: -len(x[1]))
    print("\n== Мигающие серверы (последние 8 замеров по порядку) ==")
    if not flips:
        print("Нет")
    for a, s in flips[:15]:
        print(f"{a}: {s[-8:]}  {short(latest[a]['desc'])}")

    # 5. Кандидаты в контрольные
    ctrl = [(a, rs) for a, rs in by_addr.items()
            if len(rs) >= 3 and all(r["res"] == "G" for r in rs)]
    ctrl.sort(key=lambda x: -len(x[1]))
    print("\n== Кандидаты в контрольные (3 и более замеров, все зелёные) ==")
    if not ctrl:
        print("Пока нет")
    for a, rs in ctrl[:8]:
        print(f"{a}: {len(rs)} зелёных подряд  {short(rs[-1]['desc'])}")
    print("\nКонтрольный сервер в начале и в конце сессии: если он красный, сессию не считай.")


if __name__ == "__main__":
    main()
