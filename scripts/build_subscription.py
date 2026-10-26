#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_subscription.py
Финальный шаг workflow. Делит ОДИН пул конфигов на SUBSCRIPTION_COUNT подписок.
Серверы в подписках не повторяются.

 Подписка 1 -> output/subscription.txt
 Подписка 2 -> output/subscription_cellular.txt (старое имя файла сохранено)
 Подписка 3 -> output/subscription_3.txt и т.д.

Как делится пул:
 - конфиги сортируются по sort_key (пинг с бонусами Reality, стабильных транспортов,
   маскировки, подтверждений пользователей, давления блокировок и советов ИИ;
   штраф за недоступность из РФ по output/ru_probe.json);
 - лучшие раздаются по кругу;
 - в подписке не больше MAX_SERVERS серверов и MAX_PER_COUNTRY на страну;
 - серверы из EXCLUDED_COUNTRIES (Россия) в основной пул не берутся;
 - vless без Reality и TLS не берётся;
 - подписка добивается запасными до круглого десятка (каждый запасной один раз).

Мобильная добавка (MOBILE_QUOTA серверов в КАЖДУЮ подписку), из НАШЕГО пула:
 - сначала серверы из России (MOBILE_COUNTRIES), которых нет в основной выдаче:
   лучшие по проверке из РФ (ru_probe.json), затем без данных проверки;
 - затем зарубежные серверы, которые ответили из РФ не менее чем у доли
   MOBILE_MIN_PROBE узлов;
 - названия не меняются, отдельной подписки нет;
 - без повторов между подписками и с уже вошедшими серверами;
 - список добавленных серверов пишется в output/subscription_mobile_list.txt
   (только для просмотра, без ссылок);
 - MOBILE_QUOTA = 0 выключает добавку.

Если для подписки серверов нет, её файл не перезаписывается.
Результат кодируется в base64 (формат Karing/Hiddyfi/v2rayNG).
"""
import base64
import ipaddress
import json
import os
import re
import sys
import time
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
OUT_MOBILE_LIST = os.path.join(OUT_DIR, "subscription_mobile_list.txt")
REPORTS_FILE = os.path.join(OUT_DIR, "server_reports.json")
OONI_INDEX_FILE = os.path.join(OUT_DIR, "ooni_censorship_index.json")
PROBE_FILE = os.path.join(OUT_DIR, "ru_probe.json")

SUBSCRIPTION_COUNT = 2                # на сколько подписок делить пул (2 и больше)

OONI_PRESSURE_THRESHOLD = 50          # % — выше этого порога давление считается высоким
OONI_HIGH_PRESSURE_MULTIPLIER = 1.5   # во столько раз усиливаем бонусы при высоком давлении

MAX_SERVERS = 200                     # максимум серверов в ОДНОЙ подписке
REALITY_BONUS_MS = 50
TRANSPORT_BONUS_MS = 20               # для type=xhttp/grpc/ws
CELLULAR_BONUS_MS = 80                # бонус протоколам из CELLULAR_PROTOCOLS
CELLULAR_PROTOCOLS = set()            # пусто: на LTE дело в серверах, а не в протоколе
STABLE_TRANSPORTS = {"xhttp", "grpc", "ws"}
MAX_PER_COUNTRY = 12                  # максимум серверов одной страны в ОДНОЙ подписке
EXCLUDED_COUNTRIES = {"RU"}           # серверы внутри России не берём в основной пул

ALLOW_VLESS = True                    # False = vless не берётся совсем
ALLOW_PLAIN_VLESS = False             # vless без Reality и без TLS не берётся

REPORT_BONUS_MS = 150                 # подтверждённый человеком сервер важнее
REPORT_TTL_HOURS = 48                 # сколько часов подтверждение актуально

AI_POINT_MS = 5                       # 1 балл совета ИИ = 5 мс бонуса
AI_MAX_BONUS_MS = 150                 # потолок влияния ИИ

MASK_POINT_MS = 10                    # 1 балл маскировки = 10 мс бонуса
MASK_MAX_BONUS_MS = 40                # потолок влияния оценки маскировки

PROBE_PENALTY_MS = 100                # максимальный штраф за недоступность из РФ (0 = выключено)
PROBE_TTL_HOURS = 48                  # старше этого результат проверки не учитывается

MOBILE_QUOTA = 40                     # серверов мобильной добавки в КАЖДУЮ подписку (0 = выключено)
MOBILE_COUNTRIES = {"RU"}             # страны, которые берём ТОЛЬКО для мобильной добавки
MOBILE_MIN_PROBE = 0.5                # доля российских узлов, ответивших серверу (для проверенных)

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


def load_probe():
    """Читает output/ru_probe.json (результаты проверки с российских узлов)."""
    if (PROBE_PENALTY_MS <= 0 and MOBILE_QUOTA <= 0) or not os.path.exists(PROBE_FILE):
        return {}
    try:
        with open(PROBE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def is_confirmed(display_name, reports, now):
    """True, если есть подтверждение "работает" не старше REPORT_TTL_HOURS
    и оно не было позже отменено."""
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
    """Читает output/ooni_censorship_index.json. Процент давления или None."""
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
    """Оценка маскировки по параметрам ссылки."""
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


def probe_key(raw: str):
    """host:port для vless/trojan (так записаны результаты в ru_probe.json)."""
    try:
        u = urllib.parse.urlparse(raw)
        if (u.scheme or "").lower() not in ("vless", "trojan"):
            return None
        if not u.hostname or not u.port:
            return None
        return "%s:%d" % (u.hostname.lower(), u.port)
    except Exception:
        return None


def probe_ratio(c, probe, now_ts):
    """Доля российских узлов, у которых сервер ответил (0..1).
    None: нет данных, данные старые или это Hy2."""
    if not probe:
        return None
    key = probe_key(c.get("raw", ""))
    entry = probe.get(key) if key else None
    if not entry:
        return None
    try:
        if now_ts - float(entry.get("t", 0)) > PROBE_TTL_HOURS * 3600:
            return None
        total = int(entry.get("total", 0))
        ok = int(entry.get("ok", 0))
    except (TypeError, ValueError):
        return None
    if total <= 0:
        return None
    return ok / float(total)


def probe_penalty_ms(c, probe, now_ts) -> float:
    """Штраф за недоступность из РФ: доля не ответивших узлов * PROBE_PENALTY_MS."""
    if PROBE_PENALTY_MS <= 0:
        return 0
    ratio = probe_ratio(c, probe, now_ts)
    if ratio is None:
        return 0
    return PROBE_PENALTY_MS * (1.0 - ratio)


def make_sort_key(reports, now, probe):
    pressure = load_ooni_pressure()
    high_pressure = pressure is not None and pressure >= OONI_PRESSURE_THRESHOLD
    multiplier = OONI_HIGH_PRESSURE_MULTIPLIER if high_pressure else 1
    reality_bonus = REALITY_BONUS_MS * multiplier
    cellular_bonus = CELLULAR_BONUS_MS * multiplier
    now_ts = time.time()
    if pressure is not None:
        print(f"Индикатор давления блокировок OONI (РФ): {pressure}% "
              f"({'высокое, бонусы усилены' if high_pressure else 'в норме'})")
    if probe:
        print(f"Проверка из РФ: записей {len(probe)}, штраф до {PROBE_PENALTY_MS} мс")

    def sort_key(c):
        ping = c.get("ping_ms", 9999)
        bonus = reality_bonus if c.get("security_tag") == "reality" else 0
        if extract_transport(c.get("raw", "")) in STABLE_TRANSPORTS:
            bonus += TRANSPORT_BONUS_MS
        if c.get("proto") in CELLULAR_PROTOCOLS:
            bonus += cellular_bonus

        mask_bonus = mask_info(c)["score"] * MASK_POINT_MS
        bonus += max(-MASK_MAX_BONUS_MS, min(MASK_MAX_BONUS_MS, mask_bonus))

        display_name = c.get("display_name") or c.get("remark") or "VPN"
        if is_confirmed(display_name, reports, now):
            bonus += REPORT_BONUS_MS

        ai_bonus = ai_score(rename_uri(c.get("raw", ""), display_name)) * AI_POINT_MS
        bonus += max(-AI_MAX_BONUS_MS, min(AI_MAX_BONUS_MS, ai_bonus))

        penalty = probe_penalty_ms(c, probe, now_ts)

        return ping - bonus + penalty
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
    """Делит пул на n подписок: лучшие серверы раздаются по кругу."""
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
    """Добивает подписку запасными до круглого десятка. Каждый запасной один раз."""
    target = -(-len(group) // 10) * 10
    while len(group) < target and leftovers:
        group.append(leftovers.pop(0))
    return group


def pick_mobile(configs, groups, sort_key, probe):
    """Выбирает кандидатов мобильной добавки из нашего же пула.
    Порядок: серверы из MOBILE_COUNTRIES (лучшие по проверке из РФ, потом без
    данных), затем зарубежные, ответившие из РФ не менее чем у MOBILE_MIN_PROBE.
    Серверы, уже вошедшие в подписки, пропускаются."""
    now_ts = time.time()
    seen = {c["raw"].split("#", 1)[0] for g in groups for c in g}
    cands = []
    ru_total = ru_probed = foreign_ok = 0
    for c in configs:
        base = c.get("raw", "").split("#", 1)[0]
        if not base or base in seen or not vless_allowed(c):
            continue
        seen.add(base)
        ratio = probe_ratio(c, probe, now_ts)
        is_mob_country = c.get("country_code", "??") in MOBILE_COUNTRIES
        if is_mob_country:
            ru_total += 1
            if ratio is not None:
                ru_probed += 1
                if ratio < MOBILE_MIN_PROBE:
                    continue
        else:
            if ratio is None or ratio < MOBILE_MIN_PROBE:
                continue
            foreign_ok += 1
        cands.append((0 if is_mob_country else 1,
                      -(ratio if ratio is not None else 0.0),
                      sort_key(c), c))
    cands.sort(key=lambda t: t[:3])
    print(f"Мобильная добавка: серверов из {sorted(MOBILE_COUNTRIES)} в пуле {ru_total} "
          f"(с проверкой из РФ {ru_probed}), зарубежных с ответом из РФ {foreign_ok}, "
          f"кандидатов {len(cands)}.")
    out = []
    for t in cands:
        item = dict(t[3])
        item["mobile"] = True
        out.append(item)
    return out


def add_mobile(groups, mobile):
    """Добавляет в каждую подписку до MOBILE_QUOTA серверов мобильной добавки
    по кругу, без повторов между подписками и с уже вошедшими серверами."""
    if not mobile or not groups:
        return 0
    n = len(groups)
    used = {c["raw"].split("#", 1)[0] for g in groups for c in g}
    taken = [0] * n
    added = 0
    turn = 0
    for c in mobile:
        if all(t >= MOBILE_QUOTA for t in taken):
            break
        base = c["raw"].split("#", 1)[0]
        if base in used:
            continue
        for step in range(n):
            g = (turn + step) % n
            if taken[g] < MOBILE_QUOTA and len(groups[g]) < MAX_SERVERS:
                groups[g].append(c)
                used.add(base)
                taken[g] += 1
                added += 1
                turn = (g + 1) % n
                break
    return added


def write_mobile_list(groups, probe):
    """Пишет output/subscription_mobile_list.txt: список серверов мобильной
    добавки для просмотра. Это не подписка, ссылок в файле нет."""
    now_ts = time.time()
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = ["# Мобильная добавка, обновлено %s" % stamp,
             "# Это НЕ подписка, ссылок здесь нет. Только для просмотра.",
             "# Формат: название | протокол | страна | ответ российских узлов (ru_probe)"]
    total = 0
    for i, g in enumerate(groups):
        items = [c for c in g if c.get("mobile")]
        total += len(items)
        lines.append("")
        lines.append("== %s: %d ==" % (label_for(i), len(items)))
        for c in items:
            ratio = probe_ratio(c, probe, now_ts)
            answer = "нет данных" if ratio is None else "%d%%" % round(ratio * 100)
            name = c.get("display_name") or c.get("remark") or "VPN"
            lines.append("%s | %s | %s | %s" % (
                name, c.get("proto", "?"), c.get("country_code", "??"), answer))
    lines.insert(3, "# Всего серверов: %d" % total)
    try:
        with open(OUT_MOBILE_LIST, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"Список мобильной добавки записан: {OUT_MOBILE_LIST} ({total} серверов)")
    except OSError as e:
        print(f"Список мобильной добавки не записан: {e}")


def render_subscription(configs, reports, now, probe, out_sub, out_readable, label):
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
    mobile_count = sum(1 for c in configs if c.get("mobile"))
    mobile_ru = sum(1 for c in configs if c.get("mobile") and c.get("country_code") in MOBILE_COUNTRIES)
    countries_count = len({c.get("country_code", "??") for c in configs if not c.get("mobile")})
    masks = [mask_info(c) for c in configs]
    print(f"[{label}] вошло {len(final_lines)} серверов (лимит {MAX_SERVERS}), "
          f"из них Reality: {reality_count}, Hysteria2: {hy2_count}, "
          f"стабильные транспорты (xhttp/grpc/ws): {stable_transport_count}, "
          f"подтверждено пользователями: {confirmed_count}, "
          f"стран: {countries_count} (лимит {MAX_PER_COUNTRY} на страну).")
    print(f"[{label}] мобильная добавка: {mobile_count} (из России: {mobile_ru}).")
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
    probe = load_probe()
    now = datetime.now(timezone.utc)
    sort_key = make_sort_key(reports, now, probe)

    count = max(1, SUBSCRIPTION_COUNT)
    groups, leftovers = split_pool(configs, sort_key, count)
    print(f"Пул после фильтров: {sum(len(g) for g in groups) + len(leftovers)} серверов, "
          f"делим на {count} подписок.")

    groups = [pad_to_ten(g, leftovers) for g in groups]

    if MOBILE_QUOTA > 0:
        mobile = pick_mobile(configs, groups, sort_key, probe)
        added = add_mobile(groups, mobile)
        print(f"Мобильная добавка: добавлено в подписки {added} (квота {MOBILE_QUOTA} на подписку).")
        write_mobile_list(groups, probe)

    for i, group in enumerate(groups):
        out_sub, out_readable = output_paths(i)
        render_subscription(group, reports, now, probe, out_sub, out_readable, label_for(i))


if __name__ == "__main__":
    main()
