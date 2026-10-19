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

Страховки:
 - любая ошибка сети или формата ответа -> старый файл остаётся как был,
   скрипт всё равно завершается с кодом 0 и сборку подписки не ломает;
 - если измерений меньше MIN_MEASUREMENTS, данные считаются ненадёжными и
   файл не обновляется.
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


def fetch(host, since, until):
    params = {
        "probe_cc": COUNTRY,
        "test_name": TEST_NAME,
        "since": since,
        "until": until,
        "axis_x": "probe_cc",
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


def main():
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=WINDOW_DAYS)).strftime("%Y-%m-%d")
    until = (now + timedelta(days=1)).strftime("%Y-%m-%d")

    rows = []
    for host in API_HOSTS:
        try:
            rows = extract_rows(fetch(host, since, until))
        except Exception as e:
            print("OONI: %s недоступен (%s)" % (host, e))
            continue
        if rows:
            break

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
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("OONI: давление блокировок в %s за %d дн.: %s%% (измерений: %d)"
          % (COUNTRY, WINDOW_DAYS, pressure, measurements))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("OONI: непредвиденная ошибка (%s), файл не обновлён." % e)
