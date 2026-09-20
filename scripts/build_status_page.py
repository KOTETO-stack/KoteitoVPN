#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_status_page.py
Генерирует docs/index.html — простую страницу статуса без JS-фреймворков и
внешних зависимостей (стили и графика - inline SVG), плюс ведёт docs/history.json
(последние 24 записи, по одной на каждый час) для мини-графика "сколько
серверов было последние сутки".

Чтобы страница стала доступна как сайт - один раз включи в репозитории:
Settings -> Pages -> Source: Deploy from a branch -> Branch: main /docs.
Дальше обновляется сама вместе с подпиской, никаких лишних действий не нужно.
"""
import collections
import datetime
import json
import os
import urllib.parse

ROOT = os.path.join(os.path.dirname(__file__), "..")
SUB_READABLE = os.path.join(ROOT, "output", "subscription_readable.txt")
DOCS_DIR = os.path.join(ROOT, "docs")
HISTORY_FILE = os.path.join(DOCS_DIR, "history.json")
INDEX_FILE = os.path.join(DOCS_DIR, "index.html")

MAX_HISTORY_POINTS = 24


def read_stats():
    if not os.path.exists(SUB_READABLE):
        return 0, {}, {}
    with open(SUB_READABLE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    proto_counts = collections.Counter()
    country_counts = collections.Counter()
    for line in lines:
        proto = line.split("://", 1)[0].lower()
        proto_counts[proto] += 1
        if "#" in line:
            remark = urllib.parse.unquote(line.split("#", 1)[1])
            country = remark.split(" ")[0] if remark else "?"
            country_counts[country] += 1

    return len(lines), dict(proto_counts), dict(country_counts.most_common(8))


def update_history(total):
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = []

    history.append({
        "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "total": total,
    })
    history = history[-MAX_HISTORY_POINTS:]

    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)

    return history


def render_sparkline(history):
    if not history:
        return ""
    values = [h["total"] for h in history]
    vmax = max(values) or 1
    vmin = min(values)
    span = max(vmax - vmin, 1)
    width, height = 600, 120
    step = width / max(len(values) - 1, 1)
    points = []
    for i, v in enumerate(values):
        x = i * step
        y = height - ((v - vmin) / span) * (height - 20) - 10
        points.append(f"{x:.1f},{y:.1f}")
    polyline = " ".join(points)
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg">'
        f'<polyline points="{polyline}" fill="none" stroke="#4ade80" stroke-width="2"/>'
        f"</svg>"
    )


def render_html(total, proto_counts, country_counts, history):
    proto_rows = "".join(f"<li>{p}: <b>{c}</b></li>" for p, c in sorted(proto_counts.items(), key=lambda x: -x[1]))
    country_rows = "".join(f"<li>{c}: <b>{n}</b></li>" for c, n in country_counts.items())
    updated = history[-1]["time"] if history else "нет данных"
    sparkline = render_sparkline(history)

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KoteitoVPN — статус</title>
<style>
  :root {{ color-scheme: dark light; }}
  body {{ font-family: -apple-system, system-ui, sans-serif; background:#0d1117; color:#e6edf3; max-width:640px; margin:0 auto; padding:24px 16px; }}
  h1 {{ font-size:1.4rem; }}
  .big {{ font-size:2.6rem; font-weight:700; color:#4ade80; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:12px; padding:16px; margin:16px 0; }}
  ul {{ list-style:none; padding:0; margin:0; display:flex; flex-wrap:wrap; gap:10px 20px; }}
  li {{ font-size:0.95rem; }}
  .muted {{ color:#8b949e; font-size:0.85rem; }}
</style>
</head>
<body>
  <h1>KoteitoVPN — статус подписки</h1>
  <div class="card">
    <div class="big">{total}</div>
    <div class="muted">серверов в текущей подписке</div>
  </div>
  <div class="card">
    <div class="muted" style="margin-bottom:8px;">Серверов за последние сутки</div>
    {sparkline}
  </div>
  <div class="card">
    <div class="muted" style="margin-bottom:8px;">По протоколам</div>
    <ul>{proto_rows}</ul>
  </div>
  <div class="card">
    <div class="muted" style="margin-bottom:8px;">Топ стран</div>
    <ul>{country_rows}</ul>
  </div>
  <p class="muted">Обновлено: {updated}. Обновляется автоматически каждый час.</p>
</body>
</html>"""
    return html


def main():
    os.makedirs(DOCS_DIR, exist_ok=True)
    total, proto_counts, country_counts = read_stats()
    history = update_history(total)
    html = render_html(total, proto_counts, country_counts, history)
    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Страница статуса собрана: {total} серверов, история из {len(history)} точек.")


if __name__ == "__main__":
    main()
