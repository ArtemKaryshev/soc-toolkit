"""Командная строка SOC Toolkit.

    soc-toolkit --help
    soc-toolkit ui                         запустить веб-интерфейс
    soc-toolkit ioc extract mail.eml       извлечь IOC
    soc-toolkit report alert.json -v TP    отчёт по алерту
    soc-toolkit rep check 1.2.3.4          репутация
    soc-toolkit query render bruteforce    запрос SPL/KUMA
    soc-toolkit ref mitre lsass            справочник
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from . import __version__
from .config import PACKAGE_DIR, ConfigError, Settings, app_home, load_settings, setup_logging

app = typer.Typer(help="SOC Toolkit: рабочее место аналитика SOC L1.", no_args_is_help=True,
                  rich_markup_mode="rich")
ioc_app = typer.Typer(help="Индикаторы компрометации.", no_args_is_help=True)
rep_app = typer.Typer(help="Репутация во внешних сервисах.", no_args_is_help=True)
query_app = typer.Typer(help="Запросы Splunk SPL и KUMA.", no_args_is_help=True)
ref_app = typer.Typer(help="Справочник EventID, MITRE ATT&CK, LOLBAS.", no_args_is_help=True)
cases_app = typer.Typer(help="История разборов.", no_args_is_help=True)
app.add_typer(ioc_app, name="ioc")
app.add_typer(rep_app, name="rep")
app.add_typer(query_app, name="query")
app.add_typer(ref_app, name="ref")
app.add_typer(cases_app, name="cases")

console = Console()
err = Console(stderr=True)


def _settings() -> Settings:
    try:
        s = load_settings()
    except ConfigError as e:
        err.print(str(e), style="red", markup=False, highlight=False)
        raise typer.Exit(2) from e
    setup_logging(s)
    return s


def _read_input(source: str) -> tuple[str, str]:
    """Прочитать файл или stdin ('-'). Возвращает (имя, текст)."""
    from .ioc import read_text

    if source == "-":
        return "stdin", sys.stdin.read()
    p = Path(source)
    if not p.is_file():
        err.print(f"[red]Файл не найден:[/red] {source}")
        raise typer.Exit(2)
    text, _ = read_text(p.name, p.read_bytes())
    return p.name, text


def _table(rows: list[dict[str, Any]], columns: list[str] | None = None, title: str = "") -> None:
    if not rows:
        console.print("[dim]нет данных[/dim]")
        return
    columns = columns or list(rows[0])
    t = Table(title=title, show_lines=False)
    for c in columns:
        t.add_column(c, overflow="fold")
    for r in rows:
        t.add_row(*[str(r.get(c, "")) for c in columns])
    console.print(t)


@app.callback(invoke_without_command=True)
def main(version: Annotated[bool, typer.Option("--version", help="Показать версию")] = False) -> None:
    if version:
        console.print(f"soc-toolkit {__version__}")
        raise typer.Exit()


# --------------------------------------------------------------------------- ui / config / data

@app.command()
def ui(port: int = 8501) -> None:
    """Запустить веб-интерфейс (Streamlit) на localhost."""
    app_file = PACKAGE_DIR / "ui" / "app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(app_file), "--server.port", str(port),
           "--server.address", "localhost", "--browser.gatherUsageStats", "false"]
    raise typer.Exit(subprocess.call(cmd))


@app.command("init")
def init_config(force: bool = typer.Option(False, help="Перезаписать существующий файл")) -> None:
    """Создать config.toml в домашней папке приложения из шаблона."""
    target = app_home() / "config.toml"
    if target.exists() and not force:
        console.print(f"Файл уже есть: {target}")
        raise typer.Exit()
    shutil.copy(PACKAGE_DIR / "config.example.toml", target)
    console.print(f"[green]Создан[/green] {target}. Впишите API-ключи и подтвердите политику в секции \\[reputation].")


@app.command()
def info() -> None:
    """Пути, версия справочников, состояние ключей."""
    from .reference import mitre
    from .reputation import ReputationService

    s = _settings()
    console.print(f"Версия: {__version__}")
    console.print(f"Конфиг: {s.source or 'не найден (используются значения по умолчанию)'}")
    console.print(f"Домашняя папка: {s.home}")
    console.print(f"MITRE ATT&CK: {mitre()['version']}, техник: {len(mitre()['techniques'])}")
    _table(ReputationService(s).status(), ["name", "ready", "key", "requires_key", "types"], "Провайдеры репутации")


@app.command("update-data")
def update_data() -> None:
    """Скачать свежие MITRE ATT&CK и LOLBAS (нужен интернет)."""
    from .reference.updater import update

    s = _settings()
    try:
        result = update(app_home() / "data", proxy=s.reputation.proxy)
    except Exception as e:
        err.print(f"[red]Не удалось обновить:[/red] {e}")
        raise typer.Exit(1) from e
    console.print(f"[green]Готово:[/green] {result}")


# --------------------------------------------------------------------------- IOC

@ioc_app.command("extract")
def ioc_extract(
    source: Annotated[str, typer.Argument(help="Файл (txt, log, csv, json, html, eml) или '-' для stdin")],
    fmt: Annotated[str, typer.Option("--format", "-f", help="table | csv | json | stix | list")] = "table",
    defanged: Annotated[bool, typer.Option("--defang", help="Вывести в обезвреженном виде")] = False,
    external: Annotated[bool, typer.Option("--external", help="Только внешние (кандидаты на проверку)")] = False,
    no_decode: Annotated[bool, typer.Option("--no-decode", help="Не раскодировать base64/PowerShell")] = False,
    types: Annotated[str, typer.Option(help="Типы через запятую, например ipv4,domain")] = "",
) -> None:
    """Извлечь индикаторы из файла или stdin."""
    from .ioc import Allowlist, extract, to_csv, to_json, to_stix

    s = _settings()
    _, text = _read_input(source)
    paths = [Path(s.ioc.allowlist_file)] if s.ioc.allowlist_file else []
    al = Allowlist.load(([PACKAGE_DIR / "ioc" / "allowlist.yaml"] if s.ioc.use_builtin_allowlist else []) + paths)
    found = extract(text, decode=not no_decode, allowlist=al, types=[t for t in types.split(",") if t] or None)
    if external:
        found = [i for i in found if i.is_external]
    if fmt == "csv":
        sys.stdout.write(to_csv(found, defanged))
    elif fmt == "json":
        sys.stdout.write(to_json(found, defanged) + "\n")
    elif fmt == "stix":
        sys.stdout.write(to_stix(found) + "\n")
    elif fmt == "list":
        for i in found:
            print(i.defanged if defanged else i.value)
    else:
        _table([i.as_row(defanged) for i in found], ["type", "value", "scope", "tags", "count"],
               f"Найдено индикаторов: {len(found)}")


@ioc_app.command("defang")
def ioc_defang(values: list[str]) -> None:
    """Обезвредить индикаторы."""
    from .ioc import defang

    for v in values:
        print(defang(v))


@ioc_app.command("refang")
def ioc_refang(values: list[str]) -> None:
    """Вернуть обезвреженным индикаторам рабочий вид."""
    from .ioc import refang

    for v in values:
        print(refang(v))


@ioc_app.command("decode")
def ioc_decode(source: Annotated[str, typer.Argument(help="Файл или '-'")]) -> None:
    """Раскодировать base64 / PowerShell -enc / URL-encoding."""
    from .ioc import find_encoded

    _, text = _read_input(source)
    blobs = find_encoded(text)
    if not blobs:
        console.print("[dim]закодированных фрагментов не найдено[/dim]")
    for b in blobs:
        console.rule(f"{b.kind}: {b.source[:40]}…")
        print(b.decoded)


@ioc_app.command("email")
def ioc_email(path: Path) -> None:
    """Разобрать письмо .eml: заголовки, SPF/DKIM/DMARC, вложения с хэшами, признаки фишинга."""
    from .ioc import parse_eml

    info = parse_eml(path.read_bytes())
    for k in ("subject", "sender", "reply_to", "return_path", "to", "date", "spf", "dkim", "dmarc"):
        console.print(f"[bold]{k}:[/bold] {getattr(info, k)}")
    _table([a.__dict__ for a in info.attachments], ["filename", "content_type", "size", "sha256"], "Вложения")
    for w in info.warnings:
        console.print(f"[yellow]⚠ {w}[/yellow]")


# --------------------------------------------------------------------------- отчёты

def _parse_alert_or_exit(text: str) -> Any:
    from .alerts import parse_alert

    try:
        return parse_alert(text)
    except json.JSONDecodeError as e:
        err.print(f"[red]Не удалось разобрать алерт:[/red] {e.msg}")
        raise typer.Exit(2) from e


@app.command()
def triage(
    alert_file: Annotated[str, typer.Argument(help="Алерт (JSON, NDJSON, CEF, key=value, XML) или '-'")],
    lang: Annotated[str, typer.Option("--lang", "-l", help="ru | en")] = "ru",
    as_json: Annotated[bool, typer.Option("--json", help="Вывести результат в JSON")] = False,
) -> None:
    """Рекомендация по алерту: TP/FP, уверенность, эскалация и признаки."""
    from .reports import category_title
    from .triage import assess, specific_remediation

    _, text = _read_input(alert_file)
    alert = _parse_alert_or_exit(text)
    x = assess(alert)
    if as_json:
        print(json.dumps({
            "alert": alert.name, "format": alert.source_format, "verdict": x.verdict, "certain": x.certain,
            "confidence": x.confidence, "score": x.score, "category": x.category, "outcome": x.outcome,
            "escalate": x.escalate, "escalation_reason": x.escalation_why[lang],
            "factors": [{"id": f.id, "weight": f.weight, "text": f.text(lang)} for f in x.factors + x.impact],
            "remediation": specific_remediation(alert, x, lang),
        }, ensure_ascii=False, indent=2))
        return
    cat = category_title("fp" if x.verdict == "FP" and x.certain else x.category, lang)
    color = "yellow" if not x.certain else "red" if x.verdict == "TP" else "green"
    console.print(f"[bold]{alert.name or 'Алерт без названия'}[/bold] ({alert.source_format})", highlight=False)
    console.print(f"Рекомендация: [{color}][bold]{x.label(lang)}[/bold][/{color}], уверенность {x.confidence}%, "
                  f"категория «{cat}», эскалация: "
                  f"{'[red]нужна[/red]' if x.escalate else '[green]не нужна[/green]'}", highlight=False)
    _table([{"вес": f"{f.weight:+d}" if f.weight else "0", "признак": f.text(lang)} for f in x.factors + x.impact],
           title="Признаки")
    console.print(x.escalation_why[lang], highlight=False, markup=False)


@app.command()
def report(
    alert_file: Annotated[str, typer.Argument(help="Алерт (JSON, NDJSON, CEF, key=value, XML) или '-'")],
    verdict: Annotated[str, typer.Option("--verdict", "-v", help="auto (рекомендация), TP или FP")] = "auto",
    reason: Annotated[str, typer.Option("--reason", "-r",
                                        help="Обоснование вердикта (по умолчанию составляется по уликам)")] = "",
    escalate: Annotated[bool | None, typer.Option("--escalate/--no-escalate",
                                                  help="По умолчанию по рекомендации")] = None,
    escalation_reason: Annotated[str, typer.Option("--escalation-reason")] = "",
    category: Annotated[str, typer.Option("--category", "-c", help="auto, generic, phishing, malware, ...")] = "auto",
    lang: Annotated[str, typer.Option("--lang", "-l", help="ru | en")] = "",
    fmt: Annotated[str, typer.Option("--format", "-f", help="md | html | docx")] = "md",
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Файл для сохранения")] = None,
    save_case: Annotated[bool, typer.Option("--save-case", help="Сохранить разбор в историю")] = False,
) -> None:
    """Сформировать отчёт по алерту (поля шаблона TryHackMe SOC) с вердиктом и эскалацией по рекомендации."""
    from .cases import Case, CaseStore
    from .reports import (
        ReportInput,
        categories,
        default_remediation,
        draft_escalation,
        draft_reason,
        render_docx,
        render_html,
        render_markdown,
    )
    from .triage import assess, specific_remediation

    s = _settings()
    if category != "auto" and category not in categories():
        err.print(f"[red]Неизвестная категория.[/red] Доступны: auto, {', '.join(categories())}")
        raise typer.Exit(2)
    if verdict.upper() not in ("AUTO", "TP", "FP"):
        err.print("[red]Вердикт:[/red] auto, TP или FP")
        raise typer.Exit(2)
    _, text = _read_input(alert_file)
    alert = _parse_alert_or_exit(text)
    x = assess(alert)
    verdict = x.verdict if verdict.upper() == "AUTO" else verdict.upper()
    category = x.category if category == "auto" else category
    if escalate is None:
        escalate = x.escalate if verdict == x.verdict else verdict == "TP"
    lang = lang or s.report.default_language
    reason = reason or draft_reason(alert, verdict, lang, assessment=x)
    escalation_reason = escalation_reason or draft_escalation(alert, category, lang, escalate, assessment=x)
    remediation = specific_remediation(alert, x, lang) if verdict == x.verdict else []
    remediation += [r for r in default_remediation(category, verdict, lang) if r not in remediation]
    inp = ReportInput(verdict, reason, escalate, escalation_reason, category, remediation=remediation, lang=lang,
                      analyst=s.report.analyst_name, defang=s.report.defang_indicators)
    case: Case | None = None
    store = CaseStore(s.cases_path) if save_case else None
    if store:
        case = Case(title=alert.name or "Без названия", severity=alert.severity, verdict=inp.verdict,
                    category=category, escalated=escalate, analyst=inp.analyst, source_format=alert.source_format,
                    first_seen=alert.first_seen, alert_json=text)
        inp.case_id = store.save(case, alert.iocs)
    md = render_markdown(alert, inp, s.report.custom_templates_dir)
    if store and case:
        case.report_md = md
        store.save(case)
        console.print(f"[green]Кейс сохранён:[/green] #{case.id}", highlight=False)
    if fmt == "md" and not output:
        console.print(Markdown(md))
        return
    data: bytes = (render_docx(md) if fmt == "docx" else
                   render_html(md, lang).encode() if fmt == "html" else md.encode())
    if output:
        output.write_bytes(data)
        console.print(f"[green]Сохранено:[/green] {output}")
    else:
        sys.stdout.buffer.write(data)


# --------------------------------------------------------------------------- репутация

@rep_app.command("check")
def rep_check(
    values: Annotated[list[str] | None, typer.Argument(help="Индикаторы (можно defanged)")] = None,
    file: Annotated[Path | None, typer.Option("--file", help="Файл со списком/текстом")] = None,
    providers: Annotated[str, typer.Option(help="Через запятую; по умолчанию все доступные")] = "",
    i_understand: Annotated[bool, typer.Option("--i-understand-policy",
                                               help="Подтвердить предупреждение о политике компании")] = False,
) -> None:
    """Проверить репутацию индикаторов."""
    from .ioc import extract
    from .reputation import POLICY_WARNING, ReputationService

    s = _settings()
    if not s.reputation.policy_acknowledged and not i_understand:
        err.print(f"[yellow]⚠ {POLICY_WARNING}[/yellow]")
        err.print("Подтвердите флагом --i-understand-policy или policy_acknowledged = true в config.toml.")
        raise typer.Exit(3)
    s.reputation.policy_acknowledged = True
    text = " ".join(values or []) + ("\n" + file.read_text(encoding="utf-8") if file else "")
    iocs = [i for i in extract(text) if i.type.value not in ("cve", "mitre", "path", "registry", "filename")]
    if not iocs:
        err.print("Индикаторы не распознаны.")
        raise typer.Exit(2)
    svc = ReputationService(s)
    names = [p for p in providers.split(",") if p] or None
    with console.status("Проверяю..."):
        results = svc.check(iocs, names)
    rows = []
    for a in results:
        for r in a.results:
            rows.append({"indicator": a.indicator, "итог": f"{a.verdict.icon} {a.verdict.value}",
                         "сервис": r.provider, "вердикт": r.verdict.value, "оценка": r.score,
                         "детали": r.summary or r.error, "кеш": "✓" if r.cached else ""})
    _table(rows)


@rep_app.command("status")
def rep_status() -> None:
    """Состояние провайдеров и кеша."""
    from .reputation import ReputationService

    svc = ReputationService(_settings())
    _table(svc.status(), ["name", "title", "ready", "key", "requires_key", "types", "signup"])
    console.print(f"Кеш: {svc.cache.stats()}")


@rep_app.command("clear-cache")
def rep_clear(expired: bool = typer.Option(False, help="Удалить только устаревшие записи")) -> None:
    """Очистить кеш репутации."""
    from .reputation import ReputationService

    console.print(f"Удалено записей: {ReputationService(_settings()).cache.clear(expired)}")


# --------------------------------------------------------------------------- запросы

@query_app.command("list")
def query_list() -> None:
    """Список шаблонов запросов."""
    from .queries import QueryEngine

    e = QueryEngine(_settings().queries)
    _table([{"id": t.id, "категория": t.category, "задача": t.title, "параметры": ", ".join(p.name for p in t.params),
             "MITRE": ", ".join(t.mitre)} for t in e.templates])


@query_app.command("render")
def query_render(
    template_id: str,
    param: Annotated[list[str] | None, typer.Option("--param", "-p", help="name=value")] = None,
    from_alert: Annotated[Path | None, typer.Option(help="Взять параметры из JSON алерта")] = None,
    target: Annotated[str, typer.Option(help="spl | kuma | both")] = "both",
) -> None:
    """Сгенерировать запрос по шаблону."""
    from .alerts import parse_alert
    from .queries import QueryEngine

    e = QueryEngine(_settings().queries)
    if template_id not in e.by_id:
        err.print(f"[red]Нет шаблона {template_id}.[/red] Смотрите: soc-toolkit query list")
        raise typer.Exit(2)
    params: dict[str, str] = {}
    if from_alert:
        alert_params = parse_alert(from_alert.read_text(encoding="utf-8")).query_params()
        params.update({k: v for k, v in alert_params.items() if v})
    for p in param or []:
        k, _, v = p.partition("=")
        params[k.strip()] = v
    r = e.render(template_id, params)
    if target in ("spl", "both"):
        console.rule("Splunk SPL")
        print(r.spl)
    if target in ("kuma", "both"):
        console.rule("KUMA SQL")
        print(r.kuma)


# --------------------------------------------------------------------------- справочник

@ref_app.command("event")
def ref_event(query: str) -> None:
    """Windows EventID: номер или слово."""
    from .reference import search_events

    for e in search_events(query)[:20]:
        console.print(f"[bold cyan]{e['id']}[/bold cyan] [dim]{e['log']}[/dim] [bold]{e['title']}[/bold]")
        if e.get("fields"):
            console.print(f"  поля: {e['fields']}")
        if e.get("tips"):
            console.print(f"  {e['tips']}")
        if e.get("mitre"):
            console.print(f"  MITRE: {', '.join(e['mitre'])}")


@ref_app.command("mitre")
def ref_mitre(query: str, full: bool = typer.Option(False, help="Показать описание и детект")) -> None:
    """Техника MITRE ATT&CK по ID или ключевым словам."""
    from .reference import search_techniques

    rows = search_techniques(query)
    for t in rows[: 5 if full else 30]:
        console.print(f"[bold cyan]{t['id']}[/bold cyan] [bold]{t['full_name']}[/bold] "
                      f"[dim]{', '.join(t['tactics'])}[/dim]")
        if full:
            console.print(t["description"])
            if t["detection"]:
                console.print(f"[green]Детект:[/green] {t['detection']}")
            console.print(t["url"], style="dim")
    if len(rows) > 30:
        console.print(f"[dim]… и ещё {len(rows) - 30}[/dim]")


@ref_app.command("lolbas")
def ref_lolbas(query: str) -> None:
    """LOLBAS: бинарник или техника."""
    from .reference import search_lolbas

    for e in search_lolbas(query)[:10]:
        console.print(f"[bold cyan]{e['name']}[/bold cyan] [dim]{', '.join(e['categories'])}[/dim]")
        console.print(f"  {e['description']}")
        for c in e["commands"][:4]:
            console.print(f"  [yellow]{c['category']}[/yellow] {c['command']}", highlight=False)
        console.print(f"  {e['url']}", style="dim")


# --------------------------------------------------------------------------- кейсы

@cases_app.command("list")
def cases_list(search: str = "", verdict: str = "", status: str = "", limit: int = 50) -> None:
    """Список сохранённых разборов."""
    from .cases import CaseStore

    store = CaseStore(_settings().cases_path)
    _table([{"id": c.id, "дата": c.created, "алерт": c.title, "вердикт": c.verdict, "категория": c.category,
             "эскалация": "да" if c.escalated else "", "статус": c.status}
            for c in store.search(search, verdict.upper(), status, limit=limit)])


@cases_app.command("show")
def cases_show(case_id: int) -> None:
    """Показать отчёт кейса."""
    from .cases import CaseStore

    c = CaseStore(_settings().cases_path).get(case_id)
    if not c:
        err.print("Кейс не найден")
        raise typer.Exit(2)
    console.print(Markdown(c.report_md or f"# {c.title}\n\nОтчёт не сохранён."))


@cases_app.command("stats")
def cases_stats() -> None:
    """Статистика по кейсам."""
    from .cases import CaseStore

    console.print_json(json.dumps(CaseStore(_settings().cases_path).stats(), ensure_ascii=False))


@cases_app.command("export")
def cases_export(output: Path) -> None:
    """Выгрузить все кейсы в JSON."""
    from .cases import CaseStore

    output.write_text(CaseStore(_settings().cases_path).export_json(), encoding="utf-8")
    console.print(f"[green]Сохранено:[/green] {output}")


if __name__ == "__main__":
    app()
