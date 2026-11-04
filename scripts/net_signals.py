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
 4. Замеры на реальном LTE (lte_results.txt в корне репозитория, формат как у lte_table.py):
    сервер, который в последнем замере был зелёным и не мигал, получает бонус
    LTE_SERVER_GREEN_BONUS_MS, красный и не мигавший получает штраф; у серверов без замера
    действует мягкий бонус или штраф по доле зелёных в их сети (ASN), если в сети уже есть
    не меньше LTE_ASN_MIN_SOLID замеренных серверов. Замеры сняты на одном операторе,
    поэтому веса небольшие. В лог выводится проверка слоёв по замерам.
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
LTE_SERVER_GREEN_BONUS_MS = 40    # бонус серверу, зелёному в последнем замере
LTE_SERVER_RED_PENALTY_MS = 40    # штраф серверу, красному в последнем замере
LTE_ASN_MAX_MS = 30               # потолок эффекта по сети для серверов без своего замера
LTE_ASN_MIN_SOLID = 3             # столько замеренных (не мигавших) серверов нужно в сети
LTE_ASN_PRIOR = 3                 # чем меньше замеров в сети, тем слабее её эффект


def log(msg):
    print(msg)


def asn_number(value):
    """'AS16276', 'AS16276 OVH SAS', 16276, '16276' -> 16276. Иначе None."""
    m = re.search(r"(\d+)", str(value or ""))
    return int(m.group(1)) if m else None


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
    """Читает lte_results.txt и даёт поправку серверу по его замеру или по сети."""

    def __init__(self, asn_info):
        self.ok = False
        self.servers = {}     # "ip:порт" -> запись замера
        self.by_host = {}     # "хост:порт" -> та же запись
        self.asn = {}         # номер сети -> {green, red, flaky, name}
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
                   "last": s["last"], "flaky": bool(s["flaky"]), "key": key}
            self.servers[key] = rec
            for h in s["hosts"]:
                self.by_host["%s:%s" % (h, port)] = rec
        for asn_s, n in nets.items():
            num = asn_number(asn_s)
            if num is None:
                continue
            self.asn[num] = {"green": n["green"], "red": n["red"], "flaky": n["flaky"],
                             "name": n.get("name", "")}
        self.ok = True

    def match(self, c, ip):
        port = c.get("port")
        rec = self.servers.get("%s:%s" % (ip, port)) if ip else None
        if rec is None:
            rec = self.by_host.get("%s:%s" % (str(c.get("host", "")).strip().lower(), port))
        return rec

    def adjust_ms(self, c, ip, asn):
        """Минус: бонус (сервер или сеть зелёные), плюс: штраф."""
        rec = self.match(c, ip)
        if rec is not None:
            if rec["flaky"]:
                return 0.0
            if rec["last"] == "G":
                return -float(LTE_SERVER_GREEN_BONUS_MS)
            if rec["last"] == "R":
                return float(LTE_SERVER_RED_PENALTY_MS)
        n = self.asn.get(asn) if asn is not None else None
        if n:
            solid = n["green"] + n["red"]
            if solid >= LTE_ASN_MIN_SOLID:
                share = n["green"] / float(solid)
                shrink = solid / float(solid + LTE_ASN_PRIOR)
                return (0.5 - share) * 2.0 * LTE_ASN_MAX_MS * shrink
        return 0.0


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
        self.country = {}
        self._memo = {}

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
        lte = 0.0
        if self.lte.ok:
            try:
                lte = self.lte.adjust_ms(c, ip, asn)
            except Exception:
                lte = 0.0
        res = {"ip": ip, "asn": asn, "rkn": rkn, "tspu": tspu, "tspu_name": tname, "lte": lte}
        self._memo[key] = res
        return res

    def is_rkn(self, c):
        return self.evaluate(c)["rkn"]

    def penalty_ms(self, c):
        e = self.evaluate(c)
        pen = (self.rkn_penalty if e["rkn"] else 0.0) + e["tspu"]
        return min(pen, MAX_TOTAL_PENALTY_MS)

    def country_bonus_ms(self, c):
        return self.country.get(c.get("country_code") or "??", {}).get("bonus_ms", 0.0)

    def adjust_ms(self, c):
        """Что добавить к баллу сервера: штрафы плюс поправка по замерам LTE минус бонус страны (мс)."""
        return self.penalty_ms(c) + self.evaluate(c)["lte"] - self.country_bonus_ms(c)

    # --- подготовка по всему пулу ---
    def prepare(self, configs, ratio_fn):
        """Считает приоритет стран и проверяет, не слишком ли широкие списки РКН."""
        total = len(configs)
        stats = {}
        rkn_total = 0
        lte_pool = {"G": 0, "R": 0, "flaky": 0}
        for c in configs:
            e = self.evaluate(c)
            if self.lte.ok:
                rec = self.lte.match(c, e["ip"])
                if rec is not None:
                    lte_pool["flaky" if rec["flaky"] else rec["last"]] += 1
            cc = c.get("country_code") or "??"
            s = stats.setdefault(cc, {"n": 0, "probe": [], "rkn": 0, "tspu": 0})
            s["n"] += 1
            if e["rkn"]:
                s["rkn"] += 1
                rkn_total += 1
            if e["tspu"] > 0:
                s["tspu"] += 1
            try:
                r = ratio_fn(c)
            except Exception:
                r = None
            if r is not None:
                s["probe"].append(r)

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
            "красных %d, мигающих %d (бонус %d мс, штраф %d мс; для серверов без замера "
            "эффект по сети до %d мс)."
            % (len(self.lte.servers), len(self.lte.asn), pool["G"], pool["R"], pool["flaky"],
               LTE_SERVER_GREEN_BONUS_MS, LTE_SERVER_RED_PENALTY_MS, LTE_ASN_MAX_MS))
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

    def write_country_report(self, path):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = {
                "updated_utc": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                "rkn_ranges": self.rkn.count,
                "rkn_penalty_ms": self.rkn_penalty,
                "tspu_asn_count": len(self.tspu),
                "countries": dict(sorted(self.country.items(), key=lambda kv: -kv[1]["bonus_ms"])),
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
        except OSError as e:
            log("Приоритет стран: файл не записан (%s)" % e)
