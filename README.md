# 🛡️ SOC Toolkit

Рабочее место аналитика SOC L1, которое работает на вашем компьютере. Вы вставляете алерт из Splunk или
Kaspersky KUMA, а приложение разбирает его на сущности, достаёт индикаторы, подсказывает техники MITRE ATT&CK,
предлагает поисковые запросы для расследования, проверяет репутацию (если вы это разрешили) и собирает
отчёт по шаблону TryHackMe SOC Simulator на русском или английском. Каждый разбор сохраняется в локальную
историю, поэтому повторяющийся индикатор сразу виден.

Есть веб-интерфейс (Streamlit) и командная строка. Всё, кроме проверки репутации, работает без интернета.

![CI](https://img.shields.io/badge/tests-158%20passed-brightgreen) ![coverage](https://img.shields.io/badge/coverage-88%25-green) ![python](https://img.shields.io/badge/python-3.11%2B-blue)

## Возможности

| Раздел | Что умеет |
|---|---|
| 🚨 **Разбор алерта** | Принимает JSON из Splunk (notable/CIM), KUMA (корреляционное событие с вложенными событиями), Elastic ECS, Microsoft Defender или любой другой JSON. Находит время, хосты, пользователей, IP (источник/назначение), процессы, родителей, командные строки, файлы, хэши, URL, EventID. Строит хронологию вложенных событий. Определяет техники MITRE (указанные в алерте и по 30 эвристикам). Показывает, встречались ли индикаторы в прошлых кейсах. |
| 🔎 **IOC** | IPv4/IPv6, домены, URL, e-mail, MD5/SHA1/SHA256/SHA512, CVE, техники MITRE, пути Windows, ключи реестра, подозрительные файлы. Понимает defanged-формы (`hxxp`, `[.]`, `[://]`, `[@]`). **Раскодирует** base64, PowerShell `-EncodedCommand` (в том числе вложенные) и URL-encoding и ищет IOC внутри. Делит IP на public/private/loopback/link-local, домены `.local/.corp/.lan` помечает как internal. **Allowlist** известных легитимных доменов и адресов. Читает txt, log, csv, json, html и **.eml**: в письме разбирает заголовки, SPF/DKIM/DMARC, считает хэши вложений и подсвечивает признаки фишинга. Экспорт в CSV, JSON, **STIX 2.1** и список defanged. |
| 🌐 **Репутация** | VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise Community, Shodan InternetDB, abuse.ch URLhaus. Параллельные запросы, ограничение частоты под бесплатные лимиты, повторы при сбоях, кеш в SQLite, прокси. Сводный вердикт по всем источникам. Внутренние адреса, внутренние домены и allowlist никогда не отправляются. Перед первой проверкой нужно явно подтвердить предупреждение о политике компании. |
| 🧮 **Запросы SPL / KUMA** | 34 шаблона по 13 категориям: брутфорс, password spraying, вход после неудачных, RDP, нерабочее время, Kerberoasting, изменения учёток и привилегированных групп, закодированный PowerShell, офис запускает оболочки, запуск из временных папок, доступ к LSASS, службы, задачи планировщика, Run-ключи, очистка журналов, отключение Defender, удаление теневых копий, PsExec/WMI, DNS-туннели, прокси, крупные выгрузки, почта, поиск по хэшу и др. Параметры подставляются из текущего алерта. Шаблоны лежат в YAML, свои добавляются без кода. |
| 📝 **Отчёт** | Поля TryHackMe: Time of activity, List of Affected Entities, Reason for Classifying as TP/FP, Reason for Escalating, Recommended Remediation Actions, List of Attack Indicators. Плюс хронология, таблица MITRE и вердикты репутации. Типовые рекомендации для 8 категорий. Экспорт в Markdown, HTML и Word. Шаблоны Jinja2 можно заменить своими. |
| 📚 **Справочник** | Полный MITRE ATT&CK Enterprise (706 техник с описанием и рекомендациями по обнаружению, 178 APT-группировок), полный LOLBAS (245 бинарников с командами и ссылками на детект), 110 Windows EventID (Security, System, PowerShell, RDP, WMI, TaskScheduler, Defender, Sysmon) с подсказками «на что смотреть», таблицы Logon Type, NTSTATUS, ошибок Kerberos и типов шифрования билетов. Обновление одной командой. |
| 🗂️ **Кейсы** | История разборов в SQLite: поиск по тексту и IOC, фильтры по вердикту, статусу и датам, статистика, повторяющиеся индикаторы, повторное открытие кейса, экспорт в JSON. |

## Установка

Нужен Python 3.11 или новее.

**Windows, самый простой способ:** распакуйте архив и дважды щёлкните `run.bat`. При первом запуске он создаст
окружение и установит зависимости, дальше сразу откроет приложение в браузере.

**Вручную (Windows, Linux, macOS):**

```bash
cd soc-toolkit
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -e .
soc-toolkit ui
```

Откроется http://localhost:8501. Сервер слушает только `localhost`, из сети приложение недоступно.

**Docker:**

```bash
docker build -t soc-toolkit .
docker run --rm -p 127.0.0.1:8501:8501 -v soc_toolkit_home:/data soc-toolkit
```

## Настройка

```bash
soc-toolkit init     # создаст ~/.soc_toolkit/config.toml из шаблона
soc-toolkit info     # покажет пути, версию справочников и состояние ключей
```

Все параметры с комментариями есть в [`config.example.toml`](config.example.toml). Основное:

- **Ключи API** в секции `[api_keys]` или переменными окружения `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`,
  `GREYNOISE_API_KEY`, `ABUSECH_API_KEY`. Без ключей работают GreyNoise Community и Shodan InternetDB.
- **Индексы Splunk** и лимит KUMA в секции `[queries]`.
- **Имя аналитика и язык отчёта** в секции `[report]`.
- **Прокси** для корпоративной сети: `reputation.proxy`.

Данные приложения (кеш, база кейсов, журнал работы, обновлённые справочники) лежат в `~/.soc_toolkit`.
Другую папку можно задать переменной `SOC_TOOLKIT_HOME`.

> ⚠️ **Политика компании.** Отправка индикаторов во внешние сервисы может нарушать правила вашей организации:
> владелец сервиса видит ваши запросы, а злоумышленники иногда отслеживают проверки своих IOC.
> Не отправляйте внутренние имена, адреса и хэши внутренних файлов. На работе включайте проверку репутации
> только с одобрения руководителя SOC. Приложение по умолчанию требует явного подтверждения и само не
> отправляет внутренние адреса, внутренние домены и индикаторы из allowlist.

## Командная строка

```bash
soc-toolkit ioc extract samples/phishing.eml              # IOC из письма, лога, json, html
soc-toolkit ioc extract log.txt -f stix --external > iocs.json
soc-toolkit ioc email samples/phishing.eml                # заголовки, SPF/DKIM/DMARC, вложения
soc-toolkit ioc decode script.txt                         # раскодировать -enc / base64
soc-toolkit ioc defang http://evil.com 1.2.3.4

soc-toolkit report alert.json -v TP -c malware -r "Подтверждён запуск" --escalate \
    --escalation-reason "Нужен анализ хоста" -f docx -o report.docx --save-case

soc-toolkit rep check 185.220.101.45 evil[.]com --i-understand-policy
soc-toolkit rep status

soc-toolkit query list
soc-toolkit query render bruteforce -p user=admin -p threshold=20
soc-toolkit query render by_ip --from-alert alert.json --target kuma

soc-toolkit ref event 4769
soc-toolkit ref mitre lsass
soc-toolkit ref mitre T1059.001 --full
soc-toolkit ref lolbas certutil

soc-toolkit cases list --verdict TP
soc-toolkit cases show 3
soc-toolkit update-data                                   # свежие MITRE ATT&CK и LOLBAS
```

## Типовой разбор алерта

1. **Разбор алерта:** вставьте JSON или загрузите файл. Посмотрите сущности, MITRE и хронологию.
   Если сверху появилось «🔁 индикаторы уже встречались», откройте прошлый кейс.
2. Вкладка **Индикаторы и репутация:** проверьте внешние IOC.
3. Вкладка **Запросы для расследования:** скопируйте предложенный запрос (параметры уже подставлены)
   в Splunk или KUMA и найдите связанные события.
4. При необходимости загляните в **Справочник**: что значит EventID, как работает техника, чем опасен бинарник.
5. Вкладка **Вердикт и отчёт:** выберите TP/FP и категорию. Обоснование вердикта и причина эскалации
   заполняются черновиком по уликам из алерта (время, хосты, признаки, раскодированные команды, репутация).
   Допишите то, что проверили сами, сохраните кейс и выгрузите отчёт.

Для тренировки есть примеры в [`samples/`](samples): алерт Splunk (PowerShell), алерт KUMA (подбор пароля RDP),
алерт о фишинге (переход по ссылке), текст фишингового письма
и настоящий `.eml` с макросом во вложении.

Подробнее: [docs/USAGE.md](docs/USAGE.md) (сценарии), [docs/EXTENDING.md](docs/EXTENDING.md) (свои шаблоны,
поля и провайдеры), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (устройство проекта).

## Разработка

```bash
pip install -e ".[dev]"
make check      # ruff + mypy + pytest с покрытием
```

Тесты не ходят в интернет: HTTP-ответы сервисов подменяются. CI в GitHub Actions прогоняет проверки
на Windows и Linux для Python 3.11–3.13.

## Ограничения

- Имена полей KUMA зависят от нормализаторов. Шаблоны используют стандартные поля, а для командной строки,
  типа входа и хэшей берут распространённые варианты (`DeviceCustomString1`, `DeviceCustomNumber3`,
  `FileHash`). Сверьте со своей инсталляцией и поправьте шаблоны при необходимости.
- Сжатые вложения (docx/docm/xlsx/zip) не распаковываются: считаются хэши, а макросы нужно извлекать
  отдельно, например `olevba`.
- Эвристики MITRE и сводный вердикт репутации подсказывают, а не решают. Вердикт ставит аналитик.

## Лицензия

MIT. Встроенные данные: MITRE ATT&CK® (© MITRE, ATT&CK Terms of Use) и LOLBAS Project (GPL-3.0).
