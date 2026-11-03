#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ooni_censorship_index.py

Считает общий индикатор давления блокировок в РФ по открытым данным OONI и
пишет его в output/ooni_censorship_index.json. Файл читает build_subscription.py:
при pressure_percent >= OONI_PRESSURE_THRESHOLD бонусы Reality и TCP-серверов
усиливаются. Серверы OONI не раздаёт, это только индикатор.

Как считается: OONI API (aggregation), тест web_connectivity, страна RU, за
последние WINDOW_DAYS суток. pressure_percent = (anomaly + confirmed) / measurement * 100.

Версия 2: к общему индикатору добавлены
 - operators: давление блокировок по крупнейшим российским провайдерам (по номеру сети
   probe_asn): ASN, название (если известно), число измерений, процент. Показывает, что
   у разных операторов давление разное; пока только выводится в лог сборки;
 - blocking_types: способы блокировок (dns, tcp_ip и т.п.) так, как их вернул OONI.
   Если OONI не отдаёт эту разбивку, поле остаётся прежним или пустым.
 Поля pressure_percent и остальные прежние не изменились.

Страховки:
 - любая ошибка сети или формата ответа -> старый файл остаётся как был,
   скрипт всё равно завершается с кодом 0 и сборку подписки не ломает;
 - если измерений меньше MIN_MEASUREMENTS, данные считаются ненадёжными и
   файл не обновляется;
 - если разбивка по операторам или способам не получилась, берутся значения из
   прошлого файла.
"""
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "ooni_censorship_index.json")

API_HOSTS = ["https://api.ooni.org", "https://api.ooni.io"]
COUNTRY = "RU"
TEST_NAME = "web_connectivity"
WINDOW_DAYS = 3
MIN_MEASUREMENTS = 200
TIMEOUT = 40

OPERATORS_TOP = 12                  # сколько крупнейших провайдеров показывать
OPERATOR_MIN_MEASUREMENTS = 100     # меньше измерений = провайдер не показывается
# Названия по номерам сетей (проверены по справочникам AS); у остальных только номер.
OPERATOR_NAMES = {
    "AS8359": "МТС",
    "AS31133": "МегаФон",
    "AS3216": "Билайн (Вымпелком)",
    "AS12389": "Ростелеком",
    "AS20485": "ТрансТелеКом",
}


def fetch(host, since, until, axis_x="probe_cc"):
    params = {
        "probe_cc": COUNTRY,
        "test_name": TEST_NAME,
        "since": since,
        "until": until,
        "axis_x": axis_x,
    }
    url = host + "/api/v1/aggregation?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "KoteitoVPN-ooni-index/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_rows(data):
    if isinstance(data, dict):
        for key in ("result", "results"):
            if isinstance(data.get(key), list):
                return data[key]
    if isinstance(data, list):
        return data
    return []


def fetch_rows(since, until, axis_x):
    """Строки ответа OONI по оси axis_x или пустой список."""
    for host in API_HOSTS:
        try:
            rows = extract_rows(fetch(host, since, until, axis_x))
        except Exception as e:
            print("OONI (%s): %s недоступен (%s)" % (axis_x, host, e))
            continue
        if rows:
            return rows
    return []


def _asn_key(value):
    s = str(value).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    return "AS" + s if s.isdigit() else ""


def collect_operators(since, until):
    """Давление блокировок по провайдерам (probe_asn), крупнейшие сверху."""
    rows = fetch_rows(since, until, "probe_asn")
    ops = []
    for r in rows:
        asn = _asn_key(r.get("probe_asn", ""))
        if not asn:
            continue
        m = int(r.get("measurement_count", 0) or 0)
        if m < OPERATOR_MIN_MEASUREMENTS:
            continue
        a = int(r.get("anomaly_count", 0) or 0)
        c = int(r.get("confirmed_count", 0) or 0)
        ops.append({
            "asn": asn,
            "name": OPERATOR_NAMES.get(asn, ""),
            "measurements": m,
            "anomaly": a,
            "confirmed": c,
            "pressure": round((a + c) / float(m) * 100, 1),
        })
    ops.sort(key=lambda o: -o["measurements"])
    return ops[:OPERATORS_TOP]


def collect_blocking_types(since, until):
    """Способы блокировок как их вернул OONI: {тип: число измерений}. Пусто, если не вышло."""
    rows = fetch_rows(since, until, "blocking_type")
    out = {}
    for r in rows:
        name = str(r.get("blocking_type", "") or "").strip()
        if not name:
            continue
        out[name] = int(r.get("measurement_count", 0) or 0)
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def load_old():
    try:
        with open(OUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def main():
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=WINDOW_DAYS)).strftime("%Y-%m-%d")
    until = (now + timedelta(days=1)).strftime("%Y-%m-%d")

    rows = fetch_rows(since, until, "probe_cc")

    if not rows:
        print("OONI: данных нет, файл не обновлён.")
        return

    measurements = sum(int(r.get("measurement_count", 0) or 0) for r in rows)
    anomaly = sum(int(r.get("anomaly_count", 0) or 0) for r in rows)
    confirmed = sum(int(r.get("confirmed_count", 0) or 0) for r in rows)

    if measurements < MIN_MEASUREMENTS:
        print("OONI: измерений мало (%d), файл не обновлён." % measurements)
        return

    pressure = round((anomaly + confirmed) / measurements * 100, 1)
    result = {
        "country": COUNTRY,
        "test_name": TEST_NAME,
        "pressure_percent": pressure,
        "measurements": measurements,
        "anomaly": anomaly,
        "confirmed": confirmed,
        "since": since,
        "until": until,
        "updated_utc": now.isoformat(timespec="seconds"),
    }

    old = load_old()
    try:
        ops = collect_operators(since, until)
    except Exception as e:
        print("OONI: операторы не получены (%s)" % e)
        ops = []
    try:
        types = collect_blocking_types(since, until)
    except Exception as e:
        print("OONI: способы блокировок не получены (%s)" % e)
        types = {}
    result["operators"] = ops or old.get("operators", [])
    result["blocking_types"] = types or old.get("blocking_types", {})

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("OONI: давление блокировок в %s за %d дн.: %s%% (измерений: %d)"
          % (COUNTRY, WINDOW_DAYS, pressure, measurements))
    if ops:
        for o in ops:
            print("OONI: %s %s: %s%% (измерений %d)" % (o["asn"], o["name"], o["pressure"], o["measurements"]))
    else:
        print("OONI: разбивки по операторам нет")
    print("OONI: способы блокировок: %s" % (types if types else "нет данных"))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("OONI: непредвиденная ошибка (%s), файл не обновлён." % e)
