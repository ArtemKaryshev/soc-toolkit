# Устройство проекта

```
src/soc_toolkit/
├── config.py            настройки из config.toml и окружения, пути, логирование
├── cli.py               командная строка (typer)
├── ioc/
│   ├── patterns.py      регулярные выражения и словари (TLD, расширения)
│   ├── extractor.py     извлечение, refang/defang, классификация, декодеры, allowlist, экспорт CSV/JSON/STIX
│   ├── sources.py       чтение файлов, разбор .eml
│   └── allowlist.yaml   встроенный список легитимных доменов и адресов
├── alerts/
│   ├── loader.py        текст из SIEM → dict: JSON, NDJSON, CEF, key=value, Windows XML, вложенный JSON
│   ├── parser.py        dict алерта → AlertSummary (сущности, таймлайн, MITRE, IOC, исход)
│   ├── field_map.yaml   сопоставление полей Splunk/KUMA/ECS/Wazuh/QRadar/Sentinel/Defender/CrowdStrike
│   └── mitre_hints.yaml эвристики «признак → техника»
├── triage/
│   ├── engine.py        оценка: признаки с весами → TP/FP, уверенность, эскалация, рекомендации
│   └── signals.yaml     признаки атаки и легитимной работы (регулярные выражения и веса)
├── reputation/
│   ├── base.py          Provider, RepResult, Verdict, ProviderError
│   ├── providers/       VirusTotal, AbuseIPDB, OTX, GreyNoise, Shodan InternetDB, URLhaus
│   ├── ratelimit.py     ограничитель частоты (скользящее окно)
│   ├── cache.py         кеш SQLite с TTL
│   └── service.py       политика отправки, параллельные проверки, повторы, сводный вердикт
├── queries/
│   ├── engine.py        загрузка YAML-шаблонов, рендер Jinja2 в песочнице, экранирование
│   └── templates/       auth.yaml, endpoint.yaml, network.yaml
├── reports/
│   ├── builder.py       контекст отчёта, Markdown (Jinja2), HTML, DOCX
│   ├── reasoning.py     тексты обоснования и эскалации по оценке triage
│   ├── remediation.yaml рекомендации по категориям RU/EN
│   └── templates/       report_ru.md.j2, report_en.md.j2
├── reference/
│   ├── store.py         поиск по EventID, ATT&CK, LOLBAS, группировкам
│   ├── updater.py       конвертация STIX ATT&CK и LOLBAS, обновление из интернета
│   └── data/            eventids.yaml, mitre.json.gz, lolbas.json.gz
├── cases/store.py       история разборов в SQLite, поиск, «где ещё встречался IOC»
└── ui/
    ├── app.py           Streamlit: навигация по страницам
    ├── state.py         общие ресурсы (настройки, сервисы, база) и состояние сессии
    └── tabs/            страницы: alert, ioc, reputation, queries, reference, cases, settings
```

## Поток данных при разборе алерта

```
текст алерта ─► alerts.loader ─► alerts.parse_alert ─► AlertSummary
    AlertSummary ─┬─► ioc.extract (+ decode, allowlist)
                  ├─► triage.assess (+ репутация) ─► вердикт, уверенность, эскалация, рекомендации
                  ├─► MITRE (явные ID + эвристики) ─► reference
                  ├─► query_params ─► queries.QueryEngine.suggest/render
                  ├─► reputation.ReputationService.check (внешние IOC)
                  └─► reports.reasoning + render_markdown ─► HTML / DOCX
                                 └─► cases.CaseStore.save (+ case_iocs)
```

## Принципы

- **Локальность и безопасность по умолчанию.** Интерфейс слушает только localhost. Во внешние сервисы
  уходят только внешние индикаторы и только после подтверждения политики. API-ключи не пишутся в журнал.
- **Данные отдельно от кода.** Поля алертов, эвристики, шаблоны запросов и отчётов, рекомендации
  и справочники лежат в YAML/JSON и расширяются без программирования.
- **Безопасные шаблоны.** Jinja2 работает в песочнице с `StrictUndefined`. Пользовательский ввод
  экранируется фильтрами `q`, `sq`, `like`.
- **Ядро без интерфейса.** Логика не зависит от Streamlit. CLI и веб-интерфейс вызывают одни и те же функции,
  поэтому ядро покрыто модульными тестами, а интерфейс проверяется дымовыми тестами `AppTest`.
