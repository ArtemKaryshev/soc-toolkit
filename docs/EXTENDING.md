# Расширение

Почти всё настраивается файлами без изменения кода.

## Свои шаблоны запросов

1. Создайте папку, например `~/.soc_toolkit/queries`, и укажите её в `config.toml`:
   ```toml
   [queries]
   custom_templates_dir = "~/.soc_toolkit/queries"
   ```
2. Положите туда `*.yaml` в формате встроенных шаблонов (`src/soc_toolkit/queries/templates/`):
   ```yaml
   - id: vpn_logons
     title: "Входы в VPN по пользователю"
     category: Аутентификация
     description: "Сессии VPN за период."
     mitre: [T1133]
     params:
       user: {label: "Пользователь", default: "*"}
     spl: |
       index=vpn user="{{ user|q }}" earliest={{ earliest }}
       | stats count, values(src_ip) AS ips BY user
     kuma: |
       SELECT SourceUserName, groupUniqArray(SourceAddress) AS ips, count(*) AS cnt
       FROM `events`
       WHERE DeviceProduct = 'VPN' AND SourceUserName ILIKE '{{ user|like }}'
       GROUP BY SourceUserName
       LIMIT {{ kuma_limit }}
   ```
3. Фильтры для подстановки: `q` (строка SPL в двойных кавычках), `sq` (строка SQL в одинарных),
   `like` (маска `*` → `%` для `LIKE/ILIKE`). Всегда экранируйте пользовательский ввод одним из них.
4. Шаблон с тем же `id`, что у встроенного, заменяет встроенный. Ошибочный шаблон пропускается и пишется в журнал.

Параметры с именами `user`, `host`, `ip`, `domain`, `hash`, `process` автоматически подставляются из алерта.

## Поля алертов

Если ваш SIEM кладёт данные в нестандартные поля, допишите их в `src/soc_toolkit/alerts/field_map.yaml`.
Сравнивается последний ключ пути без учёта регистра или полный путь через точку (`source.ip`).

Эвристики MITRE (регулярное выражение → техника) лежат в `src/soc_toolkit/alerts/mitre_hints.yaml`.

## Свой шаблон отчёта

Скопируйте `src/soc_toolkit/reports/templates/report_ru.md.j2` в свою папку, измените и укажите папку
в `report.custom_templates_dir`. Доступны объект алерта `a` (поля `AlertSummary`) и `ctx`
(вердикт, обоснование, сущности, индикаторы, MITRE, рекомендации). Рекомендации по категориям
редактируются в `src/soc_toolkit/reports/remediation.yaml`.

## Allowlist

Формат такой же, как у `src/soc_toolkit/ioc/allowlist.yaml`: `domains` (по суффиксу), `ips` (адреса и CIDR),
`hashes`. Путь к своему файлу указывается в `ioc.allowlist_file`. Встроенный список отключается
параметром `ioc.use_builtin_allowlist = false`.

## Свой провайдер репутации

```python
# src/soc_toolkit/reputation/providers/myti.py
from ...ioc import IOCType
from ..base import Provider, ProviderError, RepResult, Verdict


class MyTI(Provider):
    name = "myti"
    title = "Корпоративная TI-платформа"
    supported = frozenset({IOCType.IPV4, IOCType.DOMAIN})

    def check(self, ioc_type: IOCType, value: str) -> RepResult:
        r = self._get(f"https://ti.corp.local/api/lookup/{value}", headers={"Authorization": self.api_key})
        if r.status_code == 404:
            return self.result(ioc_type, value, Verdict.UNKNOWN)
        if not r.ok:
            raise ProviderError(f"HTTP {r.status_code}")
        score = r.json()["score"]
        verdict = Verdict.MALICIOUS if score > 70 else Verdict.CLEAN
        return self.result(ioc_type, value, verdict, score=str(score))
```

Зарегистрируйте класс в `providers/__init__.py` (словарь `PROVIDERS`), добавьте ключ `myti` в `[api_keys]`
и лимит в `[reputation.rate_limits]`. Кеш, лимиты, повторы, параллельность и политика отправки
работают для нового провайдера автоматически.

## Справочники

- EventID: `src/soc_toolkit/reference/data/eventids.yaml`.
- MITRE ATT&CK и LOLBAS: `soc-toolkit update-data` скачивает свежие версии в `~/.soc_toolkit/data`.
  Без интернета их можно пересобрать из локальных копий:
  `python scripts/build_reference_data.py --mitre enterprise-attack.json --lolbas-dir LOLBAS/yml`.
