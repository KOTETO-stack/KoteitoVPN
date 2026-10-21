"""Читает советы ИИ (output/ai_advice.json) и считает вес сервера.
Вес влияет только на порядок сортировки, не на то, пройдёт ли сервер проверку."""
import json
import os
import re
from urllib.parse import urlparse, parse_qs, unquote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADVICE_PATH = os.path.join(ROOT, "output", "ai_advice.json")

ALLOWED_FIELDS = {"protocol", "security", "port", "country"}
ALLOWED_PROTOCOLS = {"vless", "trojan", "hysteria2"}
ALLOWED_SECURITY = {"reality", "tls", "none"}
MAX_WEIGHT = 20

FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")


def describe(uri):
    """Разбирает ссылку на признаки: protocol, security, port, country (флаг)."""
    try:
        u = urlparse(uri.strip())
        scheme = u.scheme.lower()
        proto = "hysteria2" if scheme in ("hy2", "hysteria2") else scheme
        q = parse_qs(u.query)
        security = (q.get("security", [""])[0] or "").lower() or "none"
        if proto == "hysteria2":
            security = "tls"
        try:
            port = str(u.port or "")
        except ValueError:
            port = ""
        name = unquote(u.fragment or "")
        m = FLAG_RE.search(name)
        country = m.group(0) if m else ""
        return {"protocol": proto, "security": security, "port": port, "country": country}
    except Exception:
        return {}


def load_rules(path=ADVICE_PATH):
    """Загружает и повторно проверяет правила. Невалидные пропускаются."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []
    rules = []
    for r in data.get("rules", [])[:12]:
        try:
            field = str(r["field"])
            value = str(r["value"])
            weight = int(r["weight"])
        except Exception:
            continue
        if field not in ALLOWED_FIELDS:
            continue
        if field == "protocol" and value not in ALLOWED_PROTOCOLS:
            continue
        if field == "security" and value not in ALLOWED_SECURITY:
            continue
        if field == "port" and not value.isdigit():
            continue
        if field == "country" and not FLAG_RE.fullmatch(value):
            continue
        weight = max(-MAX_WEIGHT, min(MAX_WEIGHT, weight))
        rules.append((field, value, weight))
    return rules


_RULES = None


def score(uri):
    """Сумма весов по правилам ИИ. Больше = выше в подписке."""
    global _RULES
    if _RULES is None:
        _RULES = load_rules()
    if not _RULES:
        return 0
    d = describe(uri)
    return sum(w for field, value, w in _RULES if d.get(field) == value)
