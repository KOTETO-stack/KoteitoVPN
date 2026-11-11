#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
net_signals.py
Дополнительные сигналы для сортировки серверов. Подключается из build_subscription.py.
Сама подписку не пишет и сборку не ломает: любая ошибка здесь означает "сигнала нет".

Что считает:
 1. Списки IP, заблокированных РКН (antifilter). Скачиваются раз в RKN_TTL_HOURS часов
    и кладутся в .cache/signals (в workflow этот каталог хранится в кэше). Сервер, чей IP
    попал в список, получает штраф RKN_PENALTY_MS. Если в списки попало слишком много
    серверов пула (больше RKN_MAX_SHARE), список считается слишком широким и штраф
    смягчается до RKN_SOFT_PENALTY_MS, а в логе появляется предупреждение.
 2. Сети хостеров, на которые ТСПУ ставит ограничение "зависание после ~16 КБ"
    (data/tspu_asn.json, редактируется вручную): мягкий штраф у каждой сети свой.
 3. Приоритет стран, считается из данных, а не вручную: доля серверов страны, ответивших
    с российских узлов (ru_probe), доля серверов в списках РКН и в ТСПУ-сетях. Страна лучше
    медианной получает бонус до COUNTRY_BONUS_MAX_MS, хуже медианной штраф. Мало данных у
    страны (меньше COUNTRY_MIN_SERVERS серверов) значит бонуса нет.
 4. Замеры на реальном LTE (lte_results.txt в корне репозитория, формат как у lte_table.py).
    Версия 2 слоя:
    - Свежесть. Вес замера зависит от возраста по дате в метке («ГГГГ-ММ-ДД ЧЧ:ММ», время
      московское): до 3 дней 1.0, до 7 дней 0.8, до 14 дней 0.5, до 30 дней 0.25; старые
      строки без даты («день», «ночь», «26окт») весят LTE_LEGACY_WEIGHT.
    - Прямой замер. Сервер, зелёный в последнем замере (не мигал), получает бонус
      LTE_SERVER_GREEN_BONUS_MS * вес; красный получает штраф LTE_SERVER_RED_PENALTY_MS * вес.
      Красный замер ночью (00:00-06:59 по Москве) считается вдвое слабее: ночью красное не
      всегда мёртвое.
    - Закрепление. Сервер, зелёный на LTE не позже LTE_PIN_DAYS дней назад, build_subscription.py
      ставит в самый верх и не режет лимитом на страну.
    - Серверы без своего замера оцениваются по свежим замерам (не старше LTE_STATS_DAYS дней):
      по протоколу (если у протокола почти все замеры красные, штраф LTE_PROTO_DEAD_PENALTY_MS;
      если почти все зелёные, бонус), по подсети /24 (рядом зелёный сервер без красных: бонус,
      рядом красный без зелёных: небольшой штраф) или, если подсети нет в замерах, по сети (ASN).
      Общий потолок для таких серверов LTE_UNMEASURED_CAP_MS.
    Замеры сняты на одном операторе, поэтому слой по мере накопления данных можно усиливать.
    В лог выводится проверка слоёв по замерам.
Итог для сервера: adjust_ms(c) = штрафы + замеры LTE - бонус страны (в мс, как пинг).
"""
import bisect
import ipaddress
import json
import os
import re
import statistics
import time
import urllib.request
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
TSPU_FILE = os.path.join(DATA_DIR, "tspu_asn.json")
CACHE_DIR = os.environ.get("SIGNALS_CACHE") or os.path.join(ROOT, ".cache", "signals")

# ---------- списки РКН ----------
RKN_SOURCES = [
    ("antifilter_allyouneed", "https://antifilter.download/list/allyouneed.lst"),
    ("antifilter_community", "https://community.antifilter.download/list/community.lst"),
]
RKN_TTL_HOURS = 12            # как часто обновлять скачанные списки
RKN_MIN_ENTRIES = 500         # меньше строк = скачалась ерунда, старый файл не трогаем
RKN_DOWNLOAD_TIMEOUT = 60
RKN_PENALTY_MS = 250          # штраф серверу из списков РКН
RKN_SOFT_PENALTY_MS = 80      # штраф, если списки слишком широкие
RKN_MAX_SHARE = 0.4           # доля пула в списках, выше которой штраф смягчается
RKN_EXCLUDE = True            # серверы с IP из списков РКН в подписки не берутся совсем
RKN_EXCLUDE_MAX_SHARE = 0.6   # если в списках больше этой доли пула, списки считаются слишком
                              # широкими: серверы не убираются, остаётся только штраф

RKN_SAVE_LIST = True          # сохранять объединённый список подсетей в data/rkn_blocked_cidr.txt
RKN_LIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "rkn_blocked_cidr.txt")
RKN_SAVE_MAX_LINES = 200000   # список длиннее не сохраняем (чтобы не раздувать репозиторий)
RKN_FLAGGED_MAX = 300         # сколько попавших в списки серверов пула записывать в отчёт

# ---------- ТСПУ ----------
TSPU_DEFAULT_PENALTY_MS = 50  # штраф сети из data/tspu_asn.json, если свой не указан

# ---------- приоритет стран ----------
COUNTRY_MIN_SERVERS = 8       # меньше серверов у страны = бонуса нет
COUNTRY_MIN_PROBED = 5        # столько серверов страны должны иметь проверку из РФ
COUNTRY_BONUS_MAX_MS = 30     # потолок бонуса и штрафа страны
COUNTRY_SPAN_MS = 120         # мс за разницу качества в 1.0 (потом режется потолком)
COUNTRY_WEIGHTS = {"probe": 0.6, "rkn": 0.2, "tspu": 0.2}

MAX_TOTAL_PENALTY_MS = 300    # потолок суммы штрафов РКН и ТСПУ

# ---------- замеры на LTE ----------
LTE_FILE = os.path.join(ROOT, "lte_results.txt")
LTE_CACHE = os.path.join(CACHE_DIR, "lte_ip_info.json")   # IP -> сеть, чтобы не спрашивать ip-api каждый час
MSK = timezone(timedelta(hours=3))                        # время в метках замеров: Москва

LTE_SERVER_GREEN_BONUS_MS = 300   # бонус серверу, зелёному в последнем замере (умножается на вес свежести)
LTE_SERVER_RED_PENALTY_MS = 250   # штраф серверу, красному в последнем замере (умножается на вес свежести)
LTE_PIN_DAYS = 7                  # зелёный замер не старше стольких дней закрепляет сервер вверху подписок
LTE_LEGACY_WEIGHT = 0.35          # вес замера без читаемой даты в метке (старые строки «день», «ночь»)
LTE_NIGHT_HOURS = (0, 7)          # красный замер с 00:00 до 06:59 по Москве считается слабее
LTE_NIGHT_RED_FACTOR = 0.5        # во сколько раз слабее штраф за ночной красный замер
LTE_STATS_DAYS = 14               # в сводки по протоколам и подсетям идут замеры не старше стольких дней

LTE_ASN_MAX_MS = 60               # потолок эффекта по сети для серверов без своего замера
LTE_ASN_MIN_SOLID = 3             # столько замеренных (не мигавших) серверов нужно в сети
LTE_ASN_PRIOR = 3                 # чем меньше замеров в сети, тем слабее её эффект

LTE_NEIGHBOR_GREEN_BONUS_MS = 80  # рядом (в той же подсети /24) есть зелёный сервер и нет красных
LTE_NEIGHBOR_RED_PENALTY_MS = 30  # рядом красный сервер и нет зелёных

LTE_PROTO_MIN_N = 6               # столько свежих замеров нужно у протокола, чтобы он влиял
LTE_PROTO_DEAD_SHARE = 0.10       # доля зелёных не выше этой: протокол на LTE почти не работает
LTE_PROTO_DEAD_PENALTY_MS = 150   # штраф серверам такого протокола без своего замера
LTE_PROTO_GOOD_SHARE = 0.50       # доля зелёных не ниже этой: протокол работает хорошо
LTE_PROTO_GOOD_BONUS_MS = 40      # бонус серверам такого протокола без своего замера
LTE_PROTO_MILD_MAX_MS = 30        # потолок мягкой поправки между порогами

LTE_UNMEASURED_CAP_MS = 150       # потолок суммарной поправки серверу без своего замера


def log(msg):
    print(msg)


def asn_number(value):
    """'AS16276', 'AS16276 OVH SAS', 16276, '16276' -> 16276. Иначе None."""
    m = re.search(r"(\d+)", str(value or ""))
    return int(m.group(1)) if m else None


LABEL_DT_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{1,2}):(\d{2}))?")


def parse_label_time(label):
    """Метка замера «ГГГГ-ММ-ДД ЧЧ:ММ» -> время (московское) или None для старых меток без даты."""
    m = LABEL_DT_RE.search(label or "")
    if not m:
        return None
    try:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                        int(m.group(4) or 12), int(m.group(5) or 0), tzinfo=MSK)
    except ValueError:
        return None


def proto_from_text(text):
    """vless, trojan, hysteria2, vmess или other по названию протокола в тексте."""
    t = (text or "").lower()
    if "hysteria" in t or "hy2" in t:
        return "hysteria2"
    if "trojan" in t:
        return "trojan"
    if "vless" in t:
        return "vless"
    if "vmess" in t:
        return "vmess"
    return "other"


def prefix24(ip):
    """'163.245.42.48' -> '163.245.42' (только IPv4), иначе ''."""
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return ""
    if addr.version != 4:
        return ""
    return ".".join(str(addr).split(".")[:3])


# =====================================================================
#                          списки РКН
# =====================================================================
class IntervalSet:
    """Набор IPv4-диапазонов для быстрой проверки, входит ли адрес."""

    def __init__(self, ranges):
        ranges.sort()
        merged = []
        for s, e in ranges:
            if merged and s <= merged[-1][1] + 1:
                if e > merged[-1][1]:
                    merged[-1][1] = e
            else:
                merged.append([s, e])
        self.starts = [m[0] for m in merged]
        self.ends = [m[1] for m in merged]
        self.count = len(merged)

    def contains(self, ip_str):
        try:
            n = int(ipaddress.IPv4Address(str(ip_str).strip()))
        except ValueError:
            return False
        i = bisect.bisect_right(self.starts, n) - 1
        return i >= 0 and n <= self.ends[i]

    def cidr_lines(self):
        """Диапазоны в виде строк CIDR (по порядку адресов)."""
        out = []
        for s, e in zip(self.starts, self.ends):
            for net in ipaddress.summarize_address_range(ipaddress.IPv4Address(s), ipaddress.IPv4Address(e)):
                out.append(str(net))
        return out


def _download(url, timeout=RKN_DOWNLOAD_TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": "KoteitoVPN-signals/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def refresh_rkn():
    """Скачивает списки РКН, если кэш старше RKN_TTL_HOURS. При ошибке остаётся старый файл."""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
    except OSError as e:
        log("РКН-списки: каталог кэша недоступен (%s)" % e)
        return
    for name, url in RKN_SOURCES:
        path = os.path.join(CACHE_DIR, name + ".lst")
        exists = os.path.exists(path)
        if exists and (time.time() - os.path.getmtime(path)) < RKN_TTL_HOURS * 3600:
            continue
        try:
            text = _download(url)
            n = sum(1 for line in text.splitlines() if line.strip() and not line.startswith("#"))
            if n < RKN_MIN_ENTRIES:
                log("РКН-список %s: в ответе только %d строк, не используем%s"
                    % (name, n, ", остаётся прошлый файл" if exists else ""))
                continue
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(text)
            os.replace(tmp, path)
            log("РКН-список %s: скачано %d строк" % (name, n))
        except Exception as e:
            log("РКН-список %s: не скачан (%s)%s"
                % (name, e, ", используем прошлый файл" if exists else ""))


def load_rkn():
    """Читает скачанные списки. Возвращает (IntervalSet, число строк по источникам)."""
    ranges = []
    per_source = {}
    for name, _url in RKN_SOURCES:
        path = os.path.join(CACHE_DIR, name + ".lst")
        if not os.path.exists(path):
            continue
        n = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split()
                    if not parts or parts[0].startswith("#"):
                        continue
                    token = parts[0]
                    try:
                        if "/" in token:
                            net = ipaddress.ip_network(token, strict=False)
                            if net.version != 4:
                                continue
                            ranges.append((int(net.network_address), int(net.broadcast_address)))
                        else:
                            v = int(ipaddress.IPv4Address(token))
                            ranges.append((v, v))
                        n += 1
                    except ValueError:
                        continue
        except OSError:
            continue
        per_source[name] = n
    return IntervalSet(ranges), per_source


# =====================================================================
#                          сети ТСПУ
# =====================================================================
def load_tspu():
    """data/tspu_asn.json -> {номер_ASN: {"name": ..., "penalty": мс}}."""
    try:
        with open(TSPU_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    out = {}
    block = data.get("asn", {}) if isinstance(data, dict) else {}
    for key, val in block.items():
        n = asn_number(key)
        if n is None:
            continue
        if isinstance(val, dict):
            try:
                pen = float(val.get("penalty", TSPU_DEFAULT_PENALTY_MS))
            except (TypeError, ValueError):
                pen = TSPU_DEFAULT_PENALTY_MS
            name = str(val.get("name", ""))
        else:
            pen, name = TSPU_DEFAULT_PENALTY_MS, str(val or "")
        out[n] = {"name": name, "penalty": max(0.0, pen)}
    return out


# =====================================================================
#                          замеры на LTE
# =====================================================================
class LteLayer:
    """Читает lte_results.txt и даёт поправку серверу по его замеру, подсети, протоколу или сети."""

    def __init__(self, asn_info):
        self.ok = False
        self.now = datetime.now(timezone.utc)
        self.servers = {}     # "ip:порт" -> запись замера
        self.by_host = {}     # "хост:порт" -> та же запись
        self.asn = {}         # номер сети -> {green, red, flaky, name}
        self.proto_stats = {}     # протокол -> {"g": зелёных, "n": всего} по свежим замерам
        self.overall_share = None  # общая доля зелёных по свежим замерам
        self.net24 = {}           # подсеть /24 -> [зелёных, красных] по свежим замерам
        try:
            self._load(asn_info or {})
        except Exception as e:
            log("Слой замеров LTE выключен: %s" % e)

    def _ip_info(self, ips, asn_info):
        """Сети для IP: сначала из asn_info.json текущего пула, потом из кэша, потом ip-api."""
        rev = {}
        for _host, v in asn_info.items():
            if isinstance(v, dict) and v.get("ip") and v.get("asn"):
                rev[v["ip"]] = v
        try:
            with open(LTE_CACHE, "r", encoding="utf-8") as f:
                cache = json.load(f)
            if not isinstance(cache, dict):
                cache = {}
        except (OSError, ValueError):
            cache = {}
        info, missing = {}, []
        for ip in sorted(set(ips)):
            if ip in rev:
                v = rev[ip]
                info[ip] = {"as": ("%s %s" % (v["asn"], v.get("name", ""))).strip(),
                            "asname": v.get("name", ""), "isp": v.get("isp", ""),
                            "hosting": bool(v.get("hosting"))}
            elif ip in cache:
                info[ip] = cache[ip]
            else:
                missing.append(ip)
        if missing:
            try:
                import lte_table
                got = lte_table.lookup(missing)
                for ip, d in got.items():
                    info[ip] = d
                    cache[ip] = d
                os.makedirs(CACHE_DIR, exist_ok=True)
                with open(LTE_CACHE, "w", encoding="utf-8") as f:
                    json.dump(cache, f, ensure_ascii=False)
            except Exception as e:
                log("Замеры LTE: сети для %d IP не определены (%s)" % (len(missing), e))
        return info

    def _load(self, asn_info):
        if not os.path.exists(LTE_FILE):
            log("Замеры LTE: файла lte_results.txt нет, слой выключен.")
            return
        import lte_table
        rows = lte_table.parse_results(LTE_FILE)
        if not rows:
            log("Замеры LTE: в lte_results.txt нет замеров, слой выключен.")
            return
        ips = {h: lte_table.resolve(h) for h in sorted({r["host"] for r in rows})}
        info = self._ip_info([ip for ip in ips.values() if ip], asn_info)
        servers, nets = lte_table.build(rows, ips, info)
        for key, s in servers.items():
            _ip, _sep, port = key.rpartition(":")
            rec = {"ip": s["ip"], "asn": asn_number(s["asn"]), "g": s["g"], "r": s["r"],
                   "last": s["last"], "flaky": bool(s["flaky"]), "key": key,
                   "t": None, "desc": "", "proto": "other"}
            self.servers[key] = rec
            for h in s["hosts"]:
                self.by_host["%s:%s" % (h, port)] = rec
        for asn_s, n in nets.items():
            num = asn_number(asn_s)
            if num is None:
                continue
            self.asn[num] = {"green": n["green"], "red": n["red"], "flaky": n["flaky"],
                             "name": n.get("name", "")}
        self._attach_times()
        self.ok = True

    def _attach_times(self):
        """Время и описание последнего замера каждого сервера (по дате в метке lte_results.txt).
        Файл идёт по порядку времени, поэтому побеждает последняя строка сервера."""
        index = {}
        for key, rec in self.servers.items():
            index[key.lower()] = rec
        for key, rec in self.by_host.items():
            index[key.lower()] = rec
        try:
            with open(LTE_FILE, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError:
            return
        for line in lines:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = [p.strip() for p in s.split(";")]
            if len(parts) < 3 or parts[1].upper() not in ("G", "R"):
                continue
            rec = index.get(parts[2].lower())
            if rec is None:
                continue
            rec["t"] = parse_label_time(parts[0])
            rec["desc"] = parts[3] if len(parts) > 3 else ""
        for rec in self.servers.values():
            rec["proto"] = proto_from_text(rec.get("desc", ""))

    def match(self, c, ip):
        port = c.get("port")
        rec = self.servers.get("%s:%s" % (ip, port)) if ip else None
        if rec is None:
            rec = self.by_host.get("%s:%s" % (str(c.get("host", "")).strip().lower(), port))
        return rec

    # --- свежесть, закрепление, сводки ---
    def age_days(self, rec):
        t = rec.get("t")
        if t is None:
            return None
        return max(0.0, (self.now - t).total_seconds() / 86400.0)

    def weight(self, rec):
        """Вес замера по его возрасту."""
        age = self.age_days(rec)
        if age is None:
            return LTE_LEGACY_WEIGHT
        if age <= 3:
            return 1.0
        if age <= 7:
            return 0.8
        if age <= 14:
            return 0.5
        if age <= 30:
            return 0.25
        return 0.1

    def pinned(self, c, ip):
        """True: сервер зелёный на LTE (последний замер, не мигает) не позже LTE_PIN_DAYS дней назад."""
        rec = self.match(c, ip)
        if rec is None or rec["flaky"] or rec["last"] != "G":
            return False
        age = self.age_days(rec)
        return age is not None and age <= LTE_PIN_DAYS

    def compute_priors(self):
        """Доли зелёных по протоколам и подсетям /24 по свежим замерам (не старше LTE_STATS_DAYS дней)."""
        stats, net24 = {}, {}
        g_all = r_all = 0
        for rec in self.servers.values():
            if rec["flaky"] or rec["last"] not in ("G", "R"):
                continue
            age = self.age_days(rec)
            if age is None or age > LTE_STATS_DAYS:
                continue
            green = rec["last"] == "G"
            st = stats.setdefault(rec.get("proto") or "other", {"g": 0, "n": 0})
            st["n"] += 1
            if green:
                st["g"] += 1
                g_all += 1
            else:
                r_all += 1
            p = prefix24(rec.get("ip"))
            if p:
                cell = net24.setdefault(p, [0, 0])
                cell[0 if green else 1] += 1
        self.proto_stats = stats
        total = g_all + r_all
        self.overall_share = (g_all / float(total)) if total else None
        self.net24 = net24

    # --- поправка серверу ---
    def adjust_ms(self, c, ip, asn):
        """Минус: бонус (сервер, подсеть, протокол или сеть зелёные), плюс: штраф."""
        rec = self.match(c, ip)
        if rec is not None:
            if rec["flaky"]:
                return 0.0
            w = self.weight(rec)
            if rec["last"] == "G":
                return -float(LTE_SERVER_GREEN_BONUS_MS) * w
            if rec["last"] == "R":
                factor = 1.0
                t = rec.get("t")
                if t is not None and LTE_NIGHT_HOURS[0] <= t.hour < LTE_NIGHT_HOURS[1]:
                    factor = LTE_NIGHT_RED_FACTOR
                return float(LTE_SERVER_RED_PENALTY_MS) * w * factor
        return self.unmeasured_ms(c, ip, asn)

    def unmeasured_ms(self, c, ip, asn):
        """Поправка серверу без своего замера: протокол плюс подсеть /24 (или сеть ASN)."""
        total = 0.0
        proto = proto_from_text(c.get("proto") or "")
        st = self.proto_stats.get(proto)
        if st and st["n"] >= LTE_PROTO_MIN_N:
            share = st["g"] / float(st["n"])
            if share <= LTE_PROTO_DEAD_SHARE:
                total += LTE_PROTO_DEAD_PENALTY_MS
            elif share >= LTE_PROTO_GOOD_SHARE:
                total -= LTE_PROTO_GOOD_BONUS_MS
            elif self.overall_share is not None:
                total += (self.overall_share - share) * 2.0 * LTE_PROTO_MILD_MAX_MS

        cell = self.net24.get(prefix24(ip))
        if cell and (cell[0] > 0) != (cell[1] > 0):
            total += -float(LTE_NEIGHBOR_GREEN_BONUS_MS) if cell[0] > 0 else float(LTE_NEIGHBOR_RED_PENALTY_MS)
        else:
            n = self.asn.get(asn) if asn is not None else None
            if n:
                solid = n["green"] + n["red"]
                if solid >= LTE_ASN_MIN_SOLID:
                    share = n["green"] / float(solid)
                    shrink = solid / float(solid + LTE_ASN_PRIOR)
                    total += (0.5 - share) * 2.0 * LTE_ASN_MAX_MS * shrink
        return max(-float(LTE_UNMEASURED_CAP_MS), min(float(LTE_UNMEASURED_CAP_MS), total))


# =====================================================================
#                          главный объект
# =====================================================================
class Signals:
    def __init__(self, asn_info=None):
        self.asn_info = asn_info or {}
        self.rkn, self.rkn_sources = load_rkn()
        self.tspu = load_tspu()
        self.lte = LteLayer(self.asn_info)
        self.rkn_penalty = RKN_PENALTY_MS
        self.exclude_active = True      # prepare() выключает, если списки РКН слишком широкие
        self.country = {}
        self._memo = {}
        self._lte_memo = {}
        self._pinned = []

    # --- поиск IP и сети сервера ---
    def lookup(self, c):
        host = str(c.get("host", "")).strip().lower()
        info = self.asn_info.get(host) or {}
        ip = str(c.get("net_ip") or info.get("ip") or "").strip()
        asn = asn_number(c.get("net_asn") or info.get("asn") or "")
        return ip, asn

    def evaluate(self, c):
        key = c.get("raw") or id(c)
        hit = self._memo.get(key)
        if hit is not None:
            return hit
        ip, asn = self.lookup(c)
        rkn = bool(ip) and self.rkn.count > 0 and self.rkn.contains(ip)
        tspu, tname = 0.0, ""
        if asn is not None and asn in self.tspu:
            tspu = self.tspu[asn]["penalty"]
            tname = self.tspu[asn]["name"]
        res = {"ip": ip, "asn": asn, "rkn": rkn, "tspu": tspu, "tspu_name": tname}
        self._memo[key] = res
        return res

    def lte_ms(self, c):
        """Поправка по замерам LTE (минус: бонус). Считается после prepare(), когда готовы сводки."""
        if not self.lte.ok:
            return 0.0
        key = c.get("raw") or id(c)
        hit = self._lte_memo.get(key)
        if hit is not None:
            return hit
        e = self.evaluate(c)
        try:
            value = self.lte.adjust_ms(c, e["ip"], e["asn"])
        except Exception:
            value = 0.0
        self._lte_memo[key] = value
        return value

    def is_lte_pinned(self, c):
        """True: сервер зелёный на LTE не позже LTE_PIN_DAYS дней назад (ставится вверх подписок)."""
        if not self.lte.ok:
            return False
        try:
            return self.lte.pinned(c, self.evaluate(c)["ip"])
        except Exception:
            return False

    def is_rkn(self, c):
        return self.evaluate(c)["rkn"]

    def _lte_green(self, c, e):
        """True, если сервер напрямую замерен зелёным на мобильной сети (не мигает): замер важнее списка."""
        if not self.lte.ok:
            return False
        try:
            rec = self.lte.match(c, e["ip"])
        except Exception:
            return False
        return rec is not None and not rec.get("flaky") and rec.get("last") == "G"

    def blocked(self, c):
        """True, если сервер надо убрать из подписок: его IP в списках РКН."""
        if not RKN_EXCLUDE or not self.exclude_active:
            return False
        e = self.evaluate(c)
        return bool(e["rkn"]) and not self._lte_green(c, e)

    def drop_blocked(self, configs):
        """Убирает серверы из списков РКН. Возвращает (оставшиеся, убранные)."""
        keep, dropped = [], []
        for c in configs:
            (dropped if self.blocked(c) else keep).append(c)
        return keep, dropped

    def penalty_ms(self, c):
        e = self.evaluate(c)
        rkn_pen = self.rkn_penalty if (e["rkn"] and not self._lte_green(c, e)) else 0.0
        pen = rkn_pen + e["tspu"]
        return min(pen, MAX_TOTAL_PENALTY_MS)

    def country_bonus_ms(self, c):
        return self.country.get(c.get("country_code") or "??", {}).get("bonus_ms", 0.0)

    def adjust_ms(self, c):
        """Что добавить к баллу сервера: штрафы плюс поправка по замерам LTE минус бонус страны (мс)."""
        return self.penalty_ms(c) + self.lte_ms(c) - self.country_bonus_ms(c)

    # --- подготовка по всему пулу ---
    def prepare(self, configs, ratio_fn):
        """Считает приоритет стран, сводки по замерам LTE и проверяет, не слишком ли широкие списки РКН."""
        total = len(configs)
        stats = {}
        rkn_total = 0
        lte_pool = {"G": 0, "R": 0, "flaky": 0}
        self._flagged = []
        self._lte_memo = {}
        for c in configs:
            e = self.evaluate(c)
            if self.lte.ok:
                rec = self.lte.match(c, e["ip"])
                if rec is not None:
                    lte_pool["flaky" if rec["flaky"] else rec["last"]] += 1
                    if c.get("proto"):
                        rec["proto"] = proto_from_text(c.get("proto"))
            cc = c.get("country_code") or "??"
            s = stats.setdefault(cc, {"n": 0, "probe": [], "rkn": 0, "tspu": 0})
            s["n"] += 1
            if e["rkn"]:
                s["rkn"] += 1
                rkn_total += 1
                if len(self._flagged) < RKN_FLAGGED_MAX:
                    self._flagged.append({"ip": e["ip"], "country": cc, "asn": e["asn"],
                                          "name": c.get("display_name") or ""})
            if e["tspu"] > 0:
                s["tspu"] += 1
            try:
                r = ratio_fn(c)
            except Exception:
                r = None
            if r is not None:
                s["probe"].append(r)

        self._pinned = []
        if self.lte.ok:
            try:
                self.lte.compute_priors()
            except Exception as err:
                log("Замеры LTE: сводки по протоколам и подсетям не посчитаны (%s)" % err)
            for c in configs:
                if self.is_lte_pinned(c):
                    self._pinned.append(c.get("display_name") or c.get("remark") or "VPN")

        if total and self.rkn.count > 0 and rkn_total / float(total) > RKN_EXCLUDE_MAX_SHARE:
            self.exclude_active = False
            log("ВНИМАНИЕ: в списках РКН %d из %d серверов (%d%%), это больше порога %d%%: списки похожи на "
                "слишком широкие, серверы НЕ исключаются, остаётся только штраф"
                % (rkn_total, total, round(100.0 * rkn_total / total), round(100 * RKN_EXCLUDE_MAX_SHARE)))
        if total and self.rkn.count > 0 and rkn_total / float(total) > RKN_MAX_SHARE:
            self.rkn_penalty = RKN_SOFT_PENALTY_MS
            log("ВНИМАНИЕ: в списках РКН %d из %d серверов (%d%%), это слишком много; "
                "штраф смягчён до %d мс" % (rkn_total, total, round(100.0 * rkn_total / total),
                                           RKN_SOFT_PENALTY_MS))

        use_rkn = self.rkn.count > 0
        use_tspu = bool(self.tspu)
        eligible = {cc: s for cc, s in stats.items() if s["n"] >= COUNTRY_MIN_SERVERS}
        probe_means = [sum(s["probe"]) / len(s["probe"])
                       for s in eligible.values() if len(s["probe"]) >= COUNTRY_MIN_PROBED]
        use_probe = len(probe_means) >= 2
        median_probe = statistics.median(probe_means) if use_probe else None

        quality = {}
        for cc, s in eligible.items():
            comps = []
            if use_probe:
                if len(s["probe"]) >= COUNTRY_MIN_PROBED:
                    pm = sum(s["probe"]) / len(s["probe"])
                else:
                    pm = median_probe       # нет проверки: нейтрально
                comps.append((COUNTRY_WEIGHTS["probe"], pm))
            if use_rkn:
                comps.append((COUNTRY_WEIGHTS["rkn"], 1.0 - s["rkn"] / s["n"]))
            if use_tspu:
                comps.append((COUNTRY_WEIGHTS["tspu"], 1.0 - s["tspu"] / s["n"]))
            if comps:
                wsum = sum(w for w, _ in comps)
                quality[cc] = sum(w * v for w, v in comps) / wsum
        median_q = statistics.median(quality.values()) if len(quality) >= 3 else None

        self.country = {}
        for cc, s in stats.items():
            q = quality.get(cc)
            bonus = 0.0
            if q is not None and median_q is not None:
                bonus = max(-COUNTRY_BONUS_MAX_MS, min(COUNTRY_BONUS_MAX_MS, (q - median_q) * COUNTRY_SPAN_MS))
            self.country[cc] = {
                "servers": s["n"],
                "probed": len(s["probe"]),
                "probe_mean": round(sum(s["probe"]) / len(s["probe"]), 3) if s["probe"] else None,
                "rkn_share": round(s["rkn"] / float(s["n"]), 3),
                "tspu_share": round(s["tspu"] / float(s["n"]), 3),
                "quality": round(q, 3) if q is not None else None,
                "bonus_ms": round(bonus, 1),
            }
        self._totals = {"servers": total, "rkn": rkn_total,
                        "tspu": sum(s["tspu"] for s in stats.values())}
        self._lte_pool = lte_pool

    # --- отчёты ---
    def print_summary(self):
        t = getattr(self, "_totals", {"servers": 0, "rkn": 0, "tspu": 0})
        src = ", ".join("%s: %d" % (k, v) for k, v in self.rkn_sources.items()) or "списков нет"
        log("Сигналы: списки РКН (%s), диапазонов после слияния %d; сетей ТСПУ в файле %d."
            % (src, self.rkn.count, len(self.tspu)))
        log("Сигналы: из %d серверов пула в списках РКН %d (штраф %d мс), в ТСПУ-сетях %d."
            % (t["servers"], t["rkn"], self.rkn_penalty, t["tspu"]))
        self.print_lte()
        ranked = sorted(((cc, v) for cc, v in self.country.items() if v["quality"] is not None),
                        key=lambda kv: -kv[1]["bonus_ms"])
        if ranked:
            log("::group::Приоритет стран (бонус в мс, качество 0..1)")
            for cc, v in ranked:
                log("%s: бонус %+.1f мс, качество %.2f, серверов %d, проверено из РФ %d, "
                    "в РКН %d%%, в ТСПУ-сетях %d%%"
                    % (cc, v["bonus_ms"], v["quality"], v["servers"], v["probed"],
                       round(100 * v["rkn_share"]), round(100 * v["tspu_share"])))
            log("::endgroup::")
        else:
            log("Приоритет стран: данных пока мало, бонусов нет.")

    def print_lte(self):
        """Сводка по замерам LTE и проверка слоёв РКН и ТСПУ на этих замерах."""
        if not self.lte.ok:
            return
        pool = getattr(self, "_lte_pool", {"G": 0, "R": 0, "flaky": 0})
        log("Замеры LTE: серверов в замерах %d, сетей с данными %d; в текущем пуле: зелёных %d, "
            "красных %d, мигающих %d (бонус до %d мс, штраф до %d мс, умножаются на свежесть замера; "
            "для серверов без замера эффект до %d мс)."
            % (len(self.lte.servers), len(self.lte.asn), pool["G"], pool["R"], pool["flaky"],
               LTE_SERVER_GREEN_BONUS_MS, LTE_SERVER_RED_PENALTY_MS, LTE_UNMEASURED_CAP_MS))
        pinned = getattr(self, "_pinned", [])
        log("Замеры LTE: закреплено вверху подписок (зелёные на LTE не старше %d дн.): %d."
            % (LTE_PIN_DAYS, len(pinned)))
        if pinned:
            log("::group::Закреплённые серверы (зелёные на LTE)")
            for name in pinned:
                log(name)
            log("::endgroup::")
        if self.lte.proto_stats:
            share = ("%d%%" % round(100 * self.lte.overall_share)) if self.lte.overall_share is not None else "?"
            parts = []
            for proto, st in sorted(self.lte.proto_stats.items(), key=lambda kv: -kv[1]["n"]):
                mark = ""
                if st["n"] >= LTE_PROTO_MIN_N:
                    sh = st["g"] / float(st["n"])
                    if sh <= LTE_PROTO_DEAD_SHARE:
                        mark = " (почти не работает, штраф %d мс)" % LTE_PROTO_DEAD_PENALTY_MS
                    elif sh >= LTE_PROTO_GOOD_SHARE:
                        mark = " (работает хорошо, бонус %d мс)" % LTE_PROTO_GOOD_BONUS_MS
                parts.append("%s %d из %d%s" % (proto, st["g"], st["n"], mark))
            log("Замеры LTE по протоколам (свежие, за %d дн., зелёных всего %s): %s."
                % (LTE_STATS_DAYS, share, "; ".join(parts)))
        groups = {"в списках РКН": [0, 0], "в ТСПУ-сетях": [0, 0], "в остальных": [0, 0]}
        for rec in self.lte.servers.values():
            if rec["flaky"] or rec["last"] not in ("G", "R"):
                continue
            in_rkn = bool(rec["ip"]) and self.rkn.count > 0 and self.rkn.contains(rec["ip"])
            in_tspu = rec["asn"] is not None and rec["asn"] in self.tspu
            name = "в списках РКН" if in_rkn else ("в ТСПУ-сетях" if in_tspu else "в остальных")
            groups[name][1] += 1
            if rec["last"] == "G":
                groups[name][0] += 1
        parts = ["%s: зелёных %d из %d" % (k, g, t) for k, (g, t) in groups.items()]
        log("Проверка слоёв по замерам LTE (замеренные серверы): " + "; ".join(parts) +
            ". Если у РКН или ТСПУ доля зелёных не ниже, чем у остальных, слой надо ослабить.")

    def group_stats(self, group):
        rkn = sum(1 for c in group if self.is_rkn(c))
        tspu = sum(1 for c in group if self.evaluate(c)["tspu"] > 0)
        return rkn, tspu

    def save_rkn_list(self):
        """Пишет объединённый список подсетей РКН в data/rkn_blocked_cidr.txt (только если он изменился).
        Возвращает число строк в файле или 0."""
        if not RKN_SAVE_LIST or self.rkn.count == 0:
            return 0
        try:
            lines = self.rkn.cidr_lines()
            if len(lines) > RKN_SAVE_MAX_LINES:
                log("Список РКН не сохранён в репозиторий: %d строк (предел %d)" % (len(lines), RKN_SAVE_MAX_LINES))
                return 0
            header = ["# Подсети и адреса, заблокированные РКН (объединённые списки antifilter: %s)."
                      % ", ".join(name for name, _u in RKN_SOURCES),
                      "# Файл создаёт scripts/net_signals.py, вручную не править. Только IPv4, по одной подсети в строке."]
            text = "\n".join(header + lines) + "\n"
            try:
                with open(RKN_LIST_FILE, "r", encoding="utf-8") as f:
                    if f.read() == text:
                        return len(lines)
            except OSError:
                pass
            os.makedirs(os.path.dirname(RKN_LIST_FILE), exist_ok=True)
            with open(RKN_LIST_FILE, "w", encoding="utf-8") as f:
                f.write(text)
            log("Список РКН сохранён: data/rkn_blocked_cidr.txt (%d строк)" % len(lines))
            return len(lines)
        except Exception as e:
            log("Список РКН не сохранён (%s)" % e)
            return 0

    def write_country_report(self, path):
        """Пишет output/country_priority.json (как раньше) и рядом output/network_signals.json
        со всеми сигналами: списки РКН, сети ТСПУ, страны, замеры LTE. Из него собирается README."""
        updated = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        countries = dict(sorted(self.country.items(), key=lambda kv: -kv[1]["bonus_ms"]))
        t = getattr(self, "_totals", {"servers": 0, "rkn": 0, "tspu": 0})
        list_lines = self.save_rkn_list()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = {
                "updated_utc": updated,
                "rkn_ranges": self.rkn.count,
                "rkn_penalty_ms": self.rkn_penalty,
                "tspu_asn_count": len(self.tspu),
                "countries": countries,
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
        except OSError as e:
            log("Приоритет стран: файл не записан (%s)" % e)
            return
        try:
            pool = getattr(self, "_lte_pool", {"G": 0, "R": 0, "flaky": 0})
            full = {
                "updated_utc": updated,
                "rkn": {
                    "sources": dict(self.rkn_sources),
                    "ranges": self.rkn.count,
                    "penalty_ms": self.rkn_penalty,
                    "pool_total": t["servers"],
                    "pool_flagged": t["rkn"],
                    "flagged_servers": getattr(self, "_flagged", []),
                    "list_file": "data/rkn_blocked_cidr.txt" if list_lines else "",
                    "list_lines": list_lines,
                },
                "tspu": {
                    "asn_count": len(self.tspu),
                    "pool_flagged": t["tspu"],
                    "asn": {str(k): v for k, v in sorted(self.tspu.items())},
                },
                "countries": countries,
                "lte": {
                    "ok": bool(self.lte.ok),
                    "servers_measured": len(self.lte.servers),
                    "networks": len(self.lte.asn),
                    "pool_green": pool["G"], "pool_red": pool["R"], "pool_flaky": pool["flaky"],
                    "pinned": len(getattr(self, "_pinned", [])),
                    "protocols": {k: dict(v) for k, v in self.lte.proto_stats.items()},
                    "server_bonus_ms": LTE_SERVER_GREEN_BONUS_MS,
                    "server_penalty_ms": LTE_SERVER_RED_PENALTY_MS,
                    "network_max_ms": LTE_ASN_MAX_MS,
                },
            }
            out = os.path.join(os.path.dirname(path), "network_signals.json")
            with open(out, "w", encoding="utf-8") as f:
                json.dump(full, f, ensure_ascii=False, indent=1)
        except Exception as e:
            log("Сводка сигналов (network_signals.json) не записана (%s)" % e)
