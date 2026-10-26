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
 - серверы из EXCLUDED_COUNTRIES (Россия) не берутся из основного пула;
 - vless без Reality и TLS не берётся;
 - подписка добивается запасными до круглого десятка (каждый запасной один раз).

Мобильный список (MOBILE_QUOTA серверов в КАЖДУЮ подписку):
 - берётся прямо во время сборки из файлов igareck/vpn-configs-for-russia (GPL-3.0);
 - отдельной подписки и отдельного файла нет;
 - названия серверов не меняются (как в источнике);
 - российские серверы не исключаются;
 - берутся только те, чей порт отвечает с раннера;
 - без повторов между подписками и с уже вошедшими серверами;
 - MOBILE_QUOTA = 0 выключает добавку.

Если для подписки серверов нет, её файл не перезаписывается.
Результат кодируется в base64 (формат Karing/Hiddyfi/v2rayNG).
"""
import base64
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
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
EXCLUDED_COUNTRIES = {"RU"}           # серверы внутри России не берём из основного пула

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

MOBILE_QUOTA = 40                     # серверов из мобильного списка в КАЖДУЮ подписку (0 = выключено)
MOBILE_RAW = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"
MOBILE_SOURCES = [
    "BLACK_VLESS_RUS_mobile.txt",
    "Vless-Reality-White-Lists-Rus-Mobile.txt",
    "Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "WHITE-CIDR-RU-checked.txt",
]
MOBILE_CHECK_LIMIT = 400              # сколько серверов из мобильного списка проверить по порту
MOBILE_TCP_TIMEOUT = 3                # секунд на проверку порта
MOBILE_WORKERS = 40

HY2_SCHEMES = {"hysteria2", "hy2"}

TYPE_RE = re.compile(r"[?&]type=([a-zA-Z0-9_-]+)", re.IGNORECASE)
SECURITY_RE = re.compile(r"[?&]security=([a-zA-Z0-9_-]+)", re.IGNORECASE)
LINK_RE = re.compile(r"(?:vless|trojan)://[^\s<>\"']+", re.IGNORECASE)


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
    if PROBE_PENALTY_MS <= 0 or not os.path.exists(PROBE_FILE):
        return {}
    try:
        with open(PROBE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def interleave(lists):
    """По очереди берёт по одному элементу из каждого списка."""
    out, idx = [], 0
    while any(idx < len(l) for l in lists):
        for l in lists:
            if idx < len(l):
                out.append(l[idx])
        idx += 1
    return out


def fetch_mobile_text(name):
    url = MOBILE_RAW + urllib.parse.quote(name)
    req = urllib.request.Request(url, headers={"User-Agent": "KoteitoVPN/1.0"})
    with urllib.request.urlopen(req, timeout=40) as r:
        text = r.read().decode("utf-8", "replace")
    if "://" not in text:
        raw = text.strip()
        try:
            text = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "ignore")
        except Exception:
            pass
    return text


def parse_mobile_links(text):
    """vless только с Reality/TLS и trojan. Возвращает список словарей."""
    out = []
    for m in LINK_RE.findall(text):
        base, _, frag = m.partition("#")
        try:
            u = urllib.parse.urlparse(base)
            host, port = u.hostname, u.port
        except ValueError:
            continue
        if not host or not port:
            continue
        scheme = u.scheme.lower()
        reality = False
        if scheme == "vless":
            q = {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)}
            security = (q.get("security", "") or "").lower()
            if security not in ("reality", "tls"):
                continue
            reality = security == "reality"
        out.append({"base": base, "host": host, "port": port, "scheme": scheme,
                    "reality": reality, "name": urllib.parse.unquote(frag).strip()})
    return out


def tcp_ok(host, port):
    try:
        with socket.create_connection((host, port), timeout=MOBILE_TCP_TIMEOUT):
            return True
    except Exception:
        return False


def load_mobile_pool():
    """Качает мобильные списки igareck, проверяет порты и возвращает серверы
    в формате пула. Названия не меняются. Нет ответа от источника: пропускается."""
    if MOBILE_QUOTA <= 0:
        return []
    lists, seen = [], set()
    for name in MOBILE_SOURCES:
        try:
            text = fetch_mobile_text(name)
        except Exception as e:
            print(f"Мобильный источник {name} недоступен: {e}")
            lists.append([])
            continue
        items = []
        for it in parse_mobile_links(text):
            if it["base"] in seen:
                continue
            seen.add(it["base"])
            items.append(it)
        lists.append(items)
        print(f"Мобильный источник {name}: найдено {len(items)}")

    ordered = interleave(lists)[:MOBILE_CHECK_LIMIT]
    if not ordered:
        return []
    with ThreadPoolExecutor(MOBILE_WORKERS) as ex:
        checks = list(ex.map(lambda it: tcp_ok(it["host"], it["port"]), ordered))
    reachable = [it for it, ok in zip(ordered, checks) if ok]
    print(f"Мобильный список: проверено {len(ordered)}, порт отвечает у {len(reachable)}")

    pool = []
    for it in reachable:
        display = it["name"] or it["host"]
        pool.append({
            "raw": it["base"],
            "proto": it["scheme"],
            "security_tag": "reality" if it["reality"] else "",
            "country_code": "MOB",
            "display_name": display,
            "ping_ms": 9999,
            "mobile": True,
        })
    return pool


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


def probe_penalty_ms(c, probe, now_ts) -> float:
    """Штраф за недоступность из РФ: доля не ответивших узлов * PROBE_PENALTY_MS."""
    if PROBE_PENALTY_MS <= 0 or not probe:
        return 0
    key = probe_key(c.get("raw", ""))
    entry = probe.get(key) if key else None
    if not entry:
        return 0
    try:
        if now_ts - float(entry.get("t", 0)) > PROBE_TTL_HOURS * 3600:
            return 0
        total = int(entry.get("total", 0))
        ok = int(entry.get("ok", 0))
    except (TypeError, ValueError):
        return 0
    if total <= 0:
        return 0
    return PROBE_PENALTY_MS * (1.0 - ok / float(total))


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


def add_mobile(groups, mobile):
    """Добавляет в каждую подписку до MOBILE_QUOTA серверов из мобильного списка
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
    countries_count = len({c.get("country_code", "??") for c in configs if not c.get("mobile")})
    masks = [mask_info(c) for c in configs]
    print(f"[{label}] вошло {len(final_lines)} серверов (лимит {MAX_SERVERS}), "
          f"из них Reality: {reality_count}, Hysteria2: {hy2_count}, "
          f"стабильные транспорты (xhttp/grpc/ws): {stable_transport_count}, "
          f"подтверждено пользователями: {confirmed_count}, "
          f"стран: {countries_count} (лимит {MAX_PER_COUNTRY} на страну).")
    print(f"[{label}] из мобильного списка: {mobile_count}.")
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
        mobile = load_mobile_pool()
        added = add_mobile(groups, mobile)
        print(f"Мобильный список: добавлено в подписки {added} (квота {MOBILE_QUOTA} на подписку).")

    for i, group in enumerate(groups):
        out_sub, out_readable = output_paths(i)
        render_subscription(group, reports, now, probe, out_sub, out_readable, label_for(i))


if __name__ == "__main__":
    main()
