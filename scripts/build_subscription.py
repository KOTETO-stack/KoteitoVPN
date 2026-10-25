#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_subscription.py
Финальный шаг workflow. Делит ОДИН пул конфигов на SUBSCRIPTION_COUNT подписок
(2 и больше). Серверы в подписках не повторяются, качество у всех одинаковое.

 Подписка 1 -> output/subscription.txt
 Подписка 2 -> output/subscription_cellular.txt (старое имя файла сохранено)
 Подписка 3 -> output/subscription_3.txt, подписка 4 -> subscription_4.txt и т.д.

Как делится пул:
 - все конфиги сортируются по sort_key (пинг с бонусами Reality, стабильных
   транспортов, trojan, оценки маскировки, подтверждений пользователей,
   давления блокировок и советов ИИ из output/ai_advice.json);
 - лучшие раздаются по кругу: 1-й в подписку 1, 2-й в подписку 2, и так далее;
 - в каждой подписке не больше MAX_SERVERS серверов и не больше MAX_PER_COUNTRY
   серверов одной страны; конфиг, который не влез по этим лимитам, идёт в
   запасные;
 - серверы с country_code из EXCLUDED_COUNTRIES (Россия) не берутся вообще;
 - vless без Reality и без TLS не берётся (нестабилен); при ALLOW_VLESS = False
   vless не берётся совсем;
 - каждая подписка добивается запасными до круглого десятка (101 -> 110), но
   каждый запасной сервер используется только один раз.

Оценка маскировки (mask_info) смотрит только на параметры в ссылке и только
сдвигает порядок, серверы не отбрасывает.

Если для подписки серверов нет, её файл не перезаписывается (остаётся прошлая версия).

Остальное как раньше: remark -> "Страна Город Флаг", подтверждённые серверы
помечаются "✅", результат кодируется в base64 (формат Karing/Hiddyfi/v2rayNG).
"""
import base64
import ipaddress
import json
import os
import re
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from ai_weights import score as ai_score
except Exception:
    def ai_score(uri):
        return 0

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "masked_configs.json")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
OUT_SUB = os.path.join(OUT_DIR, "subscription.txt")
OUT_READABLE = os.path.join(OUT_DIR, "subscription_readable.txt")
OUT_SUB_CELLULAR = os.path.join(OUT_DIR, "subscription_cellular.txt")
OUT_READABLE_CELLULAR = os.path.join(OUT_DIR, "subscription_cellular_readable.txt")
REPORTS_FILE = os.path.join(OUT_DIR, "server_reports.json")
OONI_INDEX_FILE = os.path.join(OUT_DIR, "ooni_censorship_index.json")

SUBSCRIPTION_COUNT = 2                # на сколько подписок делить пул (2 и больше)

OONI_PRESSURE_THRESHOLD = 50          # % — выше этого порога давление считается высоким
OONI_HIGH_PRESSURE_MULTIPLIER = 1.5   # во столько раз усиливаем бонусы при высоком давлении

MAX_SERVERS = 200                     # максимум серверов в ОДНОЙ подписке
REALITY_BONUS_MS = 50
TRANSPORT_BONUS_MS = 20               # для type=xhttp/grpc/ws
CELLULAR_BONUS_MS = 80                # бонус протоколам из CELLULAR_PROTOCOLS
CELLULAR_PROTOCOLS = {"trojan"}       # на LTE проходят trojan и hy2; vless в бонус не входит
STABLE_TRANSPORTS = {"xhttp", "grpc", "ws"}
MAX_PER_COUNTRY = 20                  # максимум серверов одной страны в ОДНОЙ подписке
EXCLUDED_COUNTRIES = {"RU"}           # серверы внутри России не помогают обходить блокировки РКН

ALLOW_VLESS = True                    # False = vless не берётся совсем
ALLOW_PLAIN_VLESS = False             # vless без Reality и без TLS не берётся

REPORT_BONUS_MS = 150                 # подтверждённый человеком сервер важнее
REPORT_TTL_HOURS = 48                 # сколько часов подтверждение актуально

AI_POINT_MS = 5                       # 1 балл совета ИИ = 5 мс бонуса
AI_MAX_BONUS_MS = 150                 # потолок влияния ИИ (не выше подтверждения человеком)

MASK_POINT_MS = 10                    # 1 балл маскировки = 10 мс бонуса
MASK_MAX_BONUS_MS = 40                # потолок влияния оценки маскировки

HY2_SCHEMES = {"hysteria2", "hy2"}

TYPE_RE = re.compile(r"[?&]type=([a-zA-Z0-9_-]+)", re.IGNORECASE)
SECURITY_RE = re.compile(r"[?&]security=([a-zA-Z0-9_-]+)", re.IGNORECASE)


def load_reports():
    if not os.path.exists(REPORTS_FILE):
        return {}
    try:
        with open(REPORTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def is_confirmed(display_name, reports, now):
    """True, если есть подтверждение "работает" не старше REPORT_TTL_HOURS
    и оно не было позже отменено сообщением "-Имя сервера"."""
    entry = reports.get(display_name)
    if not entry or not entry.get("last_ok"):
        return False
    try:
        last_ok = datetime.fromisoformat(entry["last_ok"])
    except (ValueError, TypeError):
        return False
    if (now - last_ok) > timedelta(hours=REPORT_TTL_HOURS):
        return False
    last_fail_raw = entry.get("last_fail")
    if last_fail_raw:
        try:
            last_fail = datetime.fromisoformat(last_fail_raw)
            if last_fail > last_ok:
                return False
        except (ValueError, TypeError):
            pass
    return True


def load_ooni_pressure():
    """Читает output/ooni_censorship_index.json. Возвращает процент давления
    блокировок (0-100) или None, если данных нет."""
    if not os.path.exists(OONI_INDEX_FILE):
        return None
    try:
        with open(OONI_INDEX_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("pressure_percent")
    except (json.JSONDecodeError, OSError):
        return None


def rename_uri(raw: str, display_name: str) -> str:
    base = raw.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(display_name)}"


def extract_transport(raw: str) -> str:
    m = TYPE_RE.search(raw)
    return m.group(1).lower() if m else ""


def is_plain_vless(c) -> bool:
    """vless без Reality и без TLS (security=none или параметра нет)."""
    if c.get("proto") != "vless":
        return False
    if c.get("security_tag") == "reality":
        return False
    m = SECURITY_RE.search(c.get("raw", ""))
    security = m.group(1).lower() if m else ""
    return security not in ("reality", "tls")


def vless_allowed(c) -> bool:
    if c.get("proto") != "vless":
        return True
    if not ALLOW_VLESS:
        return False
    if not ALLOW_PLAIN_VLESS and is_plain_vless(c):
        return False
    return True


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip().strip("[]"))
        return True
    except ValueError:
        return False


def mask_info(c) -> dict:
    """Оценка маскировки по параметрам ссылки.
    Плюсы: Reality с flow vision, нормальный sni (домен), порт 443, obfs у Hy2.
    Минусы: insecure=1, пустой sni или IP вместо домена."""
    info = {"score": 0, "vision": False, "insecure": False, "ip_sni": False, "obfs": False}
    raw = c.get("raw", "")
    try:
        u = urllib.parse.urlparse(raw)
        q = {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)}
        port = u.port
        scheme = (u.scheme or "").lower()
    except Exception:
        return info

    proto = (c.get("proto") or scheme or "").lower()
    security = q.get("security", "").lower()
    is_reality = c.get("security_tag") == "reality" or security == "reality"
    is_hy2 = proto in HY2_SCHEMES or scheme in HY2_SCHEMES
    uses_tls = is_reality or security == "tls" or is_hy2 or proto == "trojan"
    sni = (q.get("sni") or q.get("peer") or q.get("servername") or "").strip()

    if uses_tls:
        if not sni:
            info["score"] -= 1
        elif _is_ip(sni):
            info["ip_sni"] = True
            info["score"] -= 1
        else:
            info["score"] += 1

    if is_reality and "vision" in q.get("flow", "").lower():
        info["vision"] = True
        info["score"] += 1

    if q.get("insecure", "").lower() in ("1", "true") or q.get("allowinsecure", "").lower() in ("1", "true"):
        info["insecure"] = True
        info["score"] -= 2

    if is_hy2 and q.get("obfs"):
        info["obfs"] = True
        info["score"] += 1

    if port == 443:
        info["score"] += 1

    return info


def make_sort_key(reports, now):
    pressure = load_ooni_pressure()
    high_pressure = pressure is not None and pressure >= OONI_PRESSURE_THRESHOLD
    multiplier = OONI_HIGH_PRESSURE_MULTIPLIER if high_pressure else 1
    reality_bonus = REALITY_BONUS_MS * multiplier
    cellular_bonus = CELLULAR_BONUS_MS * multiplier
    if pressure is not None:
        print(f"Индикатор давления блокировок OONI (РФ): {pressure}% "
              f"({'высокое, бонусы усилены' if high_pressure else 'в норме'})")

    def sort_key(c):
        ping = c.get("ping_ms", 9999)
        bonus = reality_bonus if c.get("security_tag") == "reality" else 0
        if extract_transport(c.get("raw", "")) in STABLE_TRANSPORTS:
            bonus += TRANSPORT_BONUS_MS
        if c.get("proto") in CELLULAR_PROTOCOLS:
            bonus += cellular_bonus

        # Оценка маскировки: только сдвиг порядка, с потолком.
        mask_bonus = mask_info(c)["score"] * MASK_POINT_MS
        bonus += max(-MASK_MAX_BONUS_MS, min(MASK_MAX_BONUS_MS, mask_bonus))

        display_name = c.get("display_name") or c.get("remark") or "VPN"
        if is_confirmed(display_name, reports, now):
            bonus += REPORT_BONUS_MS

        # Советы ИИ: только сдвиг порядка, с потолком.
        ai_bonus = ai_score(rename_uri(c.get("raw", ""), display_name)) * AI_POINT_MS
        bonus += max(-AI_MAX_BONUS_MS, min(AI_MAX_BONUS_MS, ai_bonus))

        return ping - bonus
    return sort_key


def output_paths(index):
    """0 -> subscription.txt, 1 -> subscription_cellular.txt (старое имя),
    2 и дальше -> subscription_3.txt, subscription_4.txt, ..."""
    if index == 0:
        return OUT_SUB, OUT_READABLE
    if index == 1:
        return OUT_SUB_CELLULAR, OUT_READABLE_CELLULAR
    n = index + 1
    return (os.path.join(OUT_DIR, "subscription_%d.txt" % n),
            os.path.join(OUT_DIR, "subscription_%d_readable.txt" % n))


def label_for(index):
    if index == 0:
        return "основная"
    if index == 1:
        return "вторая"
    return "подписка %d" % (index + 1)


def split_pool(configs, sort_key, n):
    """Делит пул на n подписок: лучшие серверы раздаются по кругу.
    Возвращает (список групп, список запасных серверов в порядке качества)."""
    seen = set()
    pool = []
    candidates = [c for c in configs if c.get("country_code", "??") not in EXCLUDED_COUNTRIES]
    before = len(candidates)
    candidates = [c for c in candidates if vless_allowed(c)]
    if before != len(candidates):
        print(f"vless отфильтрован: {before - len(candidates)} серверов "
              f"(ALLOW_VLESS={ALLOW_VLESS}, ALLOW_PLAIN_VLESS={ALLOW_PLAIN_VLESS})")
    for c in sorted(candidates, key=sort_key):
        if c["raw"] in seen:
            continue
        seen.add(c["raw"])
        pool.append(c)

    groups = [[] for _ in range(n)]
    counts = [dict() for _ in range(n)]
    leftovers = []
    turn = 0
    for c in pool:
        cc = c.get("country_code", "??")
        placed = False
        for step in range(n):
            g = (turn + step) % n
            if len(groups[g]) >= MAX_SERVERS or counts[g].get(cc, 0) >= MAX_PER_COUNTRY:
                continue
            groups[g].append(c)
            counts[g][cc] = counts[g].get(cc, 0) + 1
            turn = (g + 1) % n
            placed = True
            break
        if not placed:
            leftovers.append(c)
    return groups, leftovers


def pad_to_ten(group, leftovers):
    """Добивает подписку запасными до круглого десятка сверху. Каждый запасной
    используется только в одной подписке."""
    target = -(-len(group) // 10) * 10
    while len(group) < target and leftovers:
        group.append(leftovers.pop(0))
    return group


def render_subscription(configs, reports, now, out_sub, out_readable, label):
    if not configs:
        print(f"[{label}] серверов нет, файл не перезаписан, остаётся прошлая версия")
        return

    final_lines = []
    for c in configs:
        display_name = c.get("display_name") or c.get("remark") or "VPN"
        if is_confirmed(display_name, reports, now):
            display_name = f"{display_name} \u2705"
        final_lines.append(rename_uri(c["raw"], display_name))

    body = "\n".join(final_lines)

    with open(out_readable, "w", encoding="utf-8") as f:
        f.write(body + "\n")

    encoded = base64.b64encode(body.encode("utf-8")).decode("utf-8")
    with open(out_sub, "w", encoding="utf-8") as f:
        f.write(encoded)

    reality_count = sum(1 for c in configs if c.get("security_tag") == "reality")
    hy2_count = sum(1 for c in configs if c.get("proto") == "hysteria2")
    stable_transport_count = sum(
        1 for c in configs if extract_transport(c.get("raw", "")) in STABLE_TRANSPORTS
    )
    confirmed_count = sum(
        1 for c in configs
        if is_confirmed(c.get("display_name") or c.get("remark") or "VPN", reports, now)
    )
    countries_count = len({c.get("country_code", "??") for c in configs})
    masks = [mask_info(c) for c in configs]
    print(f"[{label}] вошло {len(final_lines)} серверов (лимит {MAX_SERVERS}), "
          f"из них Reality: {reality_count}, Hysteria2: {hy2_count}, "
          f"стабильные транспорты (xhttp/grpc/ws): {stable_transport_count}, "
          f"подтверждено пользователями: {confirmed_count}, "
          f"стран: {countries_count} (лимит {MAX_PER_COUNTRY} на страну).")
    print(f"[{label}] маскировка: vision {sum(m['vision'] for m in masks)}, "
          f"insecure {sum(m['insecure'] for m in masks)}, "
          f"sni-IP {sum(m['ip_sni'] for m in masks)}, "
          f"obfs {sum(m['obfs'] for m in masks)}.")
    print(f"[{label}] файл: {out_sub}")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    reports = load_reports()
    now = datetime.now(timezone.utc)
    sort_key = make_sort_key(reports, now)

    count = max(1, SUBSCRIPTION_COUNT)
    groups, leftovers = split_pool(configs, sort_key, count)
    print(f"Пул после фильтров: {sum(len(g) for g in groups) + len(leftovers)} серверов, "
          f"делим на {count} подписок.")

    for i, group in enumerate(groups):
        group = pad_to_ten(group, leftovers)
        out_sub, out_readable = output_paths(i)
        render_subscription(group, reports, now, out_sub, out_readable, label_for(i))


if __name__ == "__main__":
    main()
