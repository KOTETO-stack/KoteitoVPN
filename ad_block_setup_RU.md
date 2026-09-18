# Блокировка рекламы (YouTube и др.) в Karing

## Шаги в Karing

1. Открой Karing → Routing / Rule-Sets.
2. Добавь внешний rule-set:
   `https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt`
   Или готовый sing-box набор: geo/geosite/category-ads-all.srs из `MetaCubeX/meta-rules-dat`.
3. В настройках DNS: домены из rule-set → reject, остальной трафик → через VPN.
4. Сохрани профиль.

Это не встроено в скрипты подписки, потому что правила блокировки рекламы — это
слой DNS/routing клиента, а не поле в vless/trojan/hysteria2 URI.
