#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
geo_flag.py
Определяет страну, город и сеть (ASN) каждого сервера и задаёт имя display_name
в виде «флаг страна город». Имена ТОЛЬКО на русском: если гео-сервис вернул город
или страну латиницей, берётся русское название из словаря CITY_RU / COUNTRY_RU,
а для неизвестных названий делается транслитерация (список выводится в лог,
чтобы можно было дописать точное название в CITY_RU).
"""
import ipaddress
import json
import os
import re
import socket
import time
import unicodedata
import urllib.request
from collections import Counter

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "dns_checked_configs.json")
OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "geo_configs.json")
ASN_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "asn_info.json")

BATCH_URL = ("http://ip-api.com/batch?lang=ru"
             "&fields=status,countryCode,country,city,query,as,asname,isp,hosting")
BATCH_SIZE = 100
RATE_SLEEP_SEC = 4.2
EXCLUDED_COUNTRY_CODES = {"UA"}

# ---------- русские названия ----------
# Города, которые гео-сервис отдаёт латиницей. Ключ: название в нижнем регистре.
# Если в логе увидишь «транслитерировано: ...», дописывай сюда точное название.
CITY_RU = {
    "offenbach am main": "Оффенбах-на-Майне",
    "frankfurt am main": "Франкфурт-на-Майне",
    "teterboro": "Тетерборо",
    "secaucus": "Секокус",
    "longjing": "Лунцзин",
    "fo tan": "Фо Тан",
    "falkenstein": "Фалькенштайн",
    "nuremberg": "Нюрнберг",
    "nurnberg": "Нюрнберг",
    "ashburn": "Эшберн",
    "roubaix": "Рубе",
    "gravelines": "Гравлин",
    "beauharnois": "Бохарнуа",
    "council bluffs": "Каунсил-Блафс",
    "the dalles": "Те-Далс",
    "piscataway": "Пискатауэй",
    "las vegas": "Лас-Вегас",
    "new york": "Нью-Йорк",
    "los angeles": "Лос-Анджелес",
    "san jose": "Сан-Хосе",
    "san francisco": "Сан-Франциско",
    "hong kong": "Гонконг",
    "singapore": "Сингапур",
    "tokyo": "Токио",
    "seoul": "Сеул",
    "amsterdam": "Амстердам",
    "london": "Лондон",
    "paris": "Париж",
    "frankfurt": "Франкфурт",
    "stockholm": "Стокгольм",
    "warsaw": "Варшава",
    "moscow": "Москва",
    "saint petersburg": "Санкт-Петербург",
    "st petersburg": "Санкт-Петербург",
}

# Страны по коду: нужны, если гео-сервис вернул название страны не по-русски.
COUNTRY_RU = {
    "AE": "ОАЭ", "AM": "Армения", "AT": "Австрия", "AU": "Австралия", "AZ": "Азербайджан",
    "BE": "Бельгия", "BG": "Болгария", "BR": "Бразилия", "BY": "Беларусь", "CA": "Канада",
    "CH": "Швейцария", "CL": "Чили", "CN": "Китай", "CY": "Кипр", "CZ": "Чехия",
    "DE": "Германия", "DK": "Дания", "EE": "Эстония", "ES": "Испания", "FI": "Финляндия",
    "FR": "Франция", "GB": "Великобритания", "GE": "Грузия", "GR": "Греция",
    "HK": "Гонконг", "HR": "Хорватия", "HU": "Венгрия", "ID": "Индонезия", "IE": "Ирландия",
    "IL": "Израиль", "IN": "Индия", "IS": "Исландия", "IT": "Италия", "JP": "Япония",
    "KG": "Киргизия", "KR": "Южная Корея", "KZ": "Казахстан", "LT": "Литва",
    "LU": "Люксембург", "LV": "Латвия", "MD": "Молдова", "MN": "Монголия", "MO": "Макао",
    "MX": "Мексика", "MY": "Малайзия", "NL": "Нидерланды", "NO": "Норвегия",
    "NZ": "Новая Зеландия", "PL": "Польша", "PT": "Португалия", "RO": "Румыния",
    "RS": "Сербия", "RU": "Россия", "SA": "Саудовская Аравия", "SC": "Сейшелы",
    "SE": "Швеция", "SG": "Сингапур", "SI": "Словения", "SK": "Словакия", "TH": "Таиланд",
    "TR": "Турция", "TW": "Тайвань", "US": "США", "UZ": "Узбекистан", "VN": "Вьетнам",
    "ZA": "ЮАР",
}

# Правила транслитерации латиницы (длинные сочетания проверяются первыми).
_TL_RULES = [
    ("tsch", "ч"), ("sch", "ш"), ("tch", "ч"),
    ("sh", "ш"), ("ch", "ч"), ("zh", "ж"), ("kh", "х"), ("ts", "ц"), ("tz", "ц"),
    ("ph", "ф"), ("th", "т"), ("ck", "к"), ("qu", "кв"), ("ee", "и"), ("oo", "у"),
    ("ou", "у"), ("ai", "ай"), ("ay", "ей"), ("ey", "ей"), ("oy", "ой"), ("ie", "и"),
    ("ei", "ай"), ("au", "ау"), ("ya", "я"), ("yu", "ю"), ("yo", "ё"),
]
_TL_RULES.sort(key=lambda r: -len(r[0]))
_TL_SINGLE = dict(zip(
    "abcdefghijklmnopqrstuvwxyz",
    ["а", "б", "к", "д", "е", "ф", "г", "х", "и", "дж", "к", "л", "м", "н", "о", "п",
     "к", "р", "с", "т", "у", "в", "в", "кс", "и", "з"]))
_TL_SPECIAL = {"ß": "ss", "ø": "o", "æ": "ae", "œ": "oe", "ł": "l", "đ": "d"}

TRANSLITERATED = Counter()   # какие названия пришлось транслитерировать (для лога)


def _strip_accents(text):
    for k, v in _TL_SPECIAL.items():
        text = text.replace(k, v).replace(k.upper(), v.upper())
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))


def _translit_word(word):
    low = _strip_accents(word).lower()
    out = []
    i = 0
    while i < len(low):
        for src, dst in _TL_RULES:
            if low.startswith(src, i):
                out.append(dst)
                i += len(src)
                break
        else:
            ch = low[i]
            if ch == "c" and i + 1 < len(low) and low[i + 1] in "eiy":
                out.append("с")
            elif ch in _TL_SINGLE:
                out.append(_TL_SINGLE[ch])
            else:
                out.append(ch)
            i += 1
    res = "".join(out)
    if word[:1].isupper() and res:
        res = res[0].upper() + res[1:]
    return res


def transliterate(text):
    """Латиница -> кириллица по правилам выше, разделители (пробел, дефис) сохраняются."""
    parts = re.split(r"([\s\-]+)", text)
    return "".join(p if re.fullmatch(r"[\s\-]+", p or "x") else _translit_word(p) for p in parts)


def _has_latin(text):
    return bool(re.search(r"[A-Za-z\u00C0-\u024F]", text or ""))


def _has_other_script(text):
    """Буквы не латиницей и не кириллицей (китайский, арабский и т.п.)."""
    for ch in text or "":
        if ch.isalpha() and not re.match(r"[A-Za-z\u00C0-\u024F\u0400-\u04FF]", ch):
            return True
    return False


def russian_city(city):
    city = (city or "").strip()
    if not city:
        return ""
    if _has_other_script(city):
        return ""                      # иероглифы и т.п. в имя не берём
    if not _has_latin(city):
        return city                    # уже по-русски
    key = _strip_accents(city).lower().replace("-", " ")
    key = re.sub(r"\s+", " ", key).strip()
    if key in CITY_RU:
        return CITY_RU[key]
    result = transliterate(city)
    TRANSLITERATED[(city, result)] += 1
    return result


def russian_country(code, name):
    name = (name or "").strip()
    if name and not _has_latin(name) and not _has_other_script(name):
        return name
    if code in COUNTRY_RU:
        return COUNTRY_RU[code]
    if _has_other_script(name):
        return ""
    result = transliterate(name) if name else ""
    if result:
        TRANSLITERATED[(name, result)] += 1
    return result


# ---------- гео ----------
def flag_emoji(country_code: str) -> str:
    cc = country_code.upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(ord(c) - ord("A") + 0x1F1E6) for c in cc)


def resolve_ip(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except Exception:
            return None


def geo_lookup_batch(ips):
    body = json.dumps(ips).encode("utf-8")
    req = urllib.request.Request(
        BATCH_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def geo_lookup_fallback(ip):
    try:
        req = urllib.request.Request(
            f"https://ipwho.is/{ip}?lang=ru", headers={"User-Agent": "KoteitoVPN-geo-fallback"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if not data.get("success", True) is False and data.get("country_code"):
            conn = data.get("connection") or {}
            asn = conn.get("asn")
            org = (conn.get("org") or "").strip()
            return {
                "status": "success",
                "countryCode": data.get("country_code", ""),
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "as": ("AS%s %s" % (asn, org)).strip() if asn else "",
                "asname": org,
                "isp": (conn.get("isp") or "").strip(),
            }
    except Exception as e:
        print(f"[fallback geo error] {ip} -> {e}")
    return None


def net_fields(g):
    """Сеть сервера из ответа гео-сервиса: ASN, название, провайдер, датацентр."""
    as_str = (g.get("as") or "").strip()
    asn = as_str.split()[0] if as_str.upper().startswith("AS") else ""
    name = (g.get("asname") or "").strip() or " ".join(as_str.split()[1:])
    return {
        "asn": asn,
        "name": name,
        "isp": (g.get("isp") or "").strip(),
        "hosting": bool(g.get("hosting")),
    }


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    for c in configs:
        c["_ip"] = resolve_ip(c["host"])

    resolvable = [c for c in configs if c["_ip"]]
    print(f"Резолвится в IP: {len(resolvable)} из {len(configs)}")

    results = []
    for i in range(0, len(resolvable), BATCH_SIZE):
        batch = resolvable[i : i + BATCH_SIZE]
        ips = [c["_ip"] for c in batch]
        try:
            geo = geo_lookup_batch(ips)
        except Exception as e:
            print(f"[geo batch error] {e} -> fallback")
            geo = [geo_lookup_fallback(ip) for ip in ips]

        for entry, g in zip(batch, geo):
            if not g or g.get("status") != "success":
                g = geo_lookup_fallback(entry["_ip"])
                if not g:
                    continue
            cc = g.get("countryCode", "")
            if not cc or cc in EXCLUDED_COUNTRY_CODES:
                continue
            entry["country_ru"] = russian_country(cc, g.get("country", ""))
            entry["city_ru"] = russian_city(g.get("city") or "")
            entry["flag"] = flag_emoji(cc)
            entry["country_code"] = cc
            parts = [p for p in [entry["flag"], entry["country_ru"], entry["city_ru"]] if p]
            entry["display_name"] = " ".join(parts)
            nf = net_fields(g)
            entry["net_ip"] = entry["_ip"]
            entry["net_asn"] = nf["asn"]
            entry["net_name"] = nf["name"]
            entry["net_isp"] = nf["isp"]
            entry["net_hosting"] = nf["hosting"]
            results.append(entry)

        if i + BATCH_SIZE < len(resolvable):
            time.sleep(RATE_SLEEP_SEC)

    print(f"С определённой страной (без Украины): {len(results)}")

    if TRANSLITERATED:
        print("Названия латиницей, которых нет в словаре (транслитерация, можно дописать в CITY_RU):")
        for (src, dst), n in TRANSLITERATED.most_common(30):
            print(f"  {src} -> {dst} (серверов: {n})")

    # Сети серверов: файл для следующего шага и сводка в лог.
    info = {}
    for e in results:
        host = str(e.get("host", "")).strip().lower()
        if not host:
            continue
        info[host] = {
            "ip": e.get("net_ip", ""),
            "asn": e.get("net_asn", ""),
            "name": e.get("net_name", ""),
            "isp": e.get("net_isp", ""),
            "hosting": bool(e.get("net_hosting")),
        }
    try:
        os.makedirs(os.path.dirname(ASN_FILE), exist_ok=True)
        with open(ASN_FILE, "w", encoding="utf-8") as f:
            json.dump(info, f, ensure_ascii=False, indent=1)
    except OSError as e:
        print(f"[asn] файл не записан: {e}")

    known = sum(1 for e in results if e.get("net_asn"))
    hosting = sum(1 for e in results if e.get("net_hosting"))
    print(f"Сети (ASN): определено у {known} из {len(results)}, из них датацентров: {hosting}.")
    cnt = Counter((e.get("net_asn") or "?", e.get("net_name") or "") for e in results)
    for (asn, name), n in cnt.most_common(15):
        print(f"  {asn} {name}: {n}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
