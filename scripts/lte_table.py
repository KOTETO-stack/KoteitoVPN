#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lte_table.py — таблица «сеть (ASN) -> сколько серверов зелёных и красных на моём LTE».

Читает замеры из lte_results.txt (корень репозитория), определяет сеть каждого сервера
через ip-api.com (тот же источник, что у geo_flag.py), печатает таблицу в лог и в сводку
запуска (GITHUB_STEP_SUMMARY) и пишет output/lte_scores.json для следующего шага
(бонус или штраф по сети в сборке подписки).

Формат строки lte_results.txt (порядок строк = порядок по времени, новое дописывать в конец):
    метка;G или R;host:port;описание;мс
Сервер считается по IP:порт. Результат сервера = его последняя строка. Если у сервера были
и G, и R, он «мигает» (считается отдельно и в долю зелёных не входит).
"""
import ipaddress
import json
import os
import socket
import urllib.request
from collections import OrderedDict, defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(BASE, "..", "lte_results.txt")
OUT_JSON = os.path.join(BASE, "..", "output", "lte_scores.json")
SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY")
IP_API = "http://ip-api.com/batch"


def parse_results(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            p = [x.strip() for x in line.split(";")]
            if len(p) < 3 or p[1].upper() not in ("G", "R"):
                print("пропущена строка %d (нужно: метка;G или R;host:port): %s" % (n, line))
                continue
            host, _, port = p[2].rpartition(":")
            if not host or not port.isdigit():
                print("пропущена строка %d (нет host:port): %s" % (n, line))
                continue
            rows.append({
                "tag": p[0], "res": p[1].upper(), "host": host.lower(), "port": int(port),
                "note": p[3] if len(p) > 3 else "",
            })
    return rows


def resolve(host):
    """IP-адрес для хоста (или None, если имя не резолвится)."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def lookup(ips):
    """Сеть для списка IP через ip-api.com (пачки по 100). Возвращает {ip: данные}."""
    info = {}
    ips = sorted(set(ips))
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        body = json.dumps([
            {"query": ip, "fields": "status,query,as,asname,isp,hosting,countryCode"} for ip in chunk
        ]).encode("utf-8")
        req = urllib.request.Request(IP_API, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                data = json.loads(r.read().decode("utf-8"))
        except Exception as e:
            print("ip-api.com не ответил: %s" % e)
            continue
        for d in data:
            if d.get("status") == "success":
                info[d.get("query")] = d
    return info


def build(rows, ips, info):
    """Сводит замеры по серверам (IP:порт), затем по сетям (ASN)."""
    servers = OrderedDict()
    for r in rows:
        ip = ips.get(r["host"])
        key = "%s:%d" % (ip or r["host"], r["port"])
        s = servers.setdefault(key, {"ip": ip, "hosts": set(), "g": 0, "r": 0, "last": None, "note": ""})
        s["hosts"].add(r["host"])
        s["g" if r["res"] == "G" else "r"] += 1
        s["last"] = r["res"]
        if r["note"]:
            s["note"] = r["note"]

    nets = {}
    for key, s in servers.items():
        d = info.get(s["ip"]) if s["ip"] else None
        asn = d["as"].split()[0] if d and d.get("as") else "неизвестно"
        n = nets.setdefault(asn, {
            "name": (d.get("asname") or d.get("isp") or "") if d else "",
            "dc": 0, "servers": 0, "green": 0, "red": 0, "flaky": 0, "keys": [],
        })
        n["servers"] += 1
        n["keys"].append(key)
        if d and d.get("hosting"):
            n["dc"] += 1
        s["asn"] = asn
        s["flaky"] = s["g"] > 0 and s["r"] > 0
        if s["flaky"]:
            n["flaky"] += 1
        elif s["last"] == "G":
            n["green"] += 1
        else:
            n["red"] += 1
    for n in nets.values():
        solid = n["green"] + n["red"]
        n["green_share"] = round(n["green"] / solid, 2) if solid else None
    return servers, nets


def render(servers, nets, rows):
    out = []
    out.append("## Сети (ASN): зелёные и красные на LTE")
    out.append("")
    out.append("Замеров: %d, серверов (IP:порт): %d, сетей: %d. Доля зелёных считается только по серверам, "
               "которые не мигали. Выборка маленькая, это подсказка, а не вывод." % (len(rows), len(servers), len(nets)))
    out.append("")
    out.append("| Сеть (ASN) | Название | Серверов | Зелёных | Красных | Мигают | Доля зелёных |")
    out.append("|---|---|---|---|---|---|---|")
    order = sorted(nets.items(), key=lambda kv: (-kv[1]["servers"], kv[0]))
    for asn, n in order:
        share = "-" if n["green_share"] is None else "%d%%" % round(n["green_share"] * 100)
        name = n["name"] + (" (DC)" if n["dc"] == n["servers"] and n["servers"] else "")
        out.append("| %s | %s | %d | %d | %d | %d | %s |" % (
            asn, name or "-", n["servers"], n["green"], n["red"], n["flaky"], share))
    flaky = [(k, s) for k, s in servers.items() if s["flaky"]]
    if flaky:
        out.append("")
        out.append("### Мигают (были и зелёные, и красные)")
        out.append("")
        for k, s in flaky:
            out.append("- %s: зелёных %d, красных %d, сейчас %s, сеть %s" % (
                k, s["g"], s["r"], "зелёный" if s["last"] == "G" else "красный", s["asn"]))
    unknown = [k for k, s in servers.items() if s["asn"] == "неизвестно"]
    if unknown:
        out.append("")
        out.append("### Сеть не определена: %s" % ", ".join(unknown))
    return "\n".join(out) + "\n"


def main():
    rows = parse_results(RESULTS)
    if not rows:
        print("В lte_results.txt нет ни одной строки с замером.")
        return
    ips = {}
    for h in sorted({r["host"] for r in rows}):
        ips[h] = resolve(h)
    info = lookup([ip for ip in ips.values() if ip])
    servers, nets = build(rows, ips, info)
    text = render(servers, nets, rows)
    print(text)
    if SUMMARY:
        with open(SUMMARY, "a", encoding="utf-8") as f:
            f.write(text)
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    result = {
        "asn": {a: {k: v for k, v in n.items() if k != "keys"} for a, n in nets.items()},
        "servers": {k: {"asn": s["asn"], "green": s["g"], "red": s["r"],
                        "last": s["last"], "flaky": s["flaky"]} for k, s in servers.items()},
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("Записано: output/lte_scores.json")


if __name__ == "__main__":
    main()
