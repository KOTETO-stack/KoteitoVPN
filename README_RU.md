# KoteitoVPN — авто-подписка для Karing / Hiddyfi

## Что делает система

**Workflow 1 — `collect_and_test.yml`** (каждые 6 часов):
сбор конфигов из `sources.txt` → фильтр (без WARP/Tor/мусора) → TCP-пинг (≤500мс) →
DNS-проверка → `output/raw_servers.txt`.

**Workflow 2 — `build_subscription.yml`** (через 20 мин после первого):
берёт `raw_servers.txt` → повторная фильтрация/пинг → гео-определение через
ip-api.com (страна/город на русском + флаг) → маскировка Xray (uTLS fingerprint) →
лимит 150 серверов, лучшие по пингу → `output/subscription.txt` — финальная
ссылка для Karing/Hiddyfi.

Никаких внешних Python-библиотек не нужно — всё на стандартной библиотеке.
Репозиторий публичный → Actions-минуты бесплатны без лимита 2000 мин/мес.

## Установка

1. Залей всю структуру в публичный репозиторий.
2. Settings → Actions → General → Workflow permissions → Read and write permissions.
3. Запусти оба workflow вручную первый раз (Actions → Run workflow).
4. Ссылка подписки:
   `https://raw.githubusercontent.com/<аккаунт>/<репо>/main/output/subscription.txt`

## Пункты, изменённые от исходного ТЗ

- Тор-мосты не совместимы с Trojan/VLESS/Hysteria2 технически — не встроены.
- "Маскировка под Яндекс" заменена на реально работающий uTLS fingerprint (fp=chrome).
- Блокировка рекламы YouTube настраивается в самом Karing (см. ad_block_setup_RU.md).

## Исправленный баг: build_subscription падал за 0 секунд

Причина была в heredoc внутри `run: |` в yml — YAML сдвигает отступ у закрывающего
маркера, bash требует его без отступа. Исправлено: логика вынесена в
`scripts/raw_to_json.py`, никакого inline-питона в yml больше нет.

## Проверка

Если workflow отрабатывает подозрительно быстро и `output/subscription.txt` пустой:
1. Permissions на Read/write не включены → git push у бота не проходит молча.
2. `sources.txt` не найден по пути — не переноси файл из корня.
3. Все источники недоступны — смотри лог шага `collect_sources.py`.
