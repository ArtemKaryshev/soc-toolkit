import pytest

from soc_toolkit.config import QuerySettings
from soc_toolkit.queries import QueryEngine, esc_spl, esc_sql, like

ENGINE = QueryEngine()


@pytest.mark.parametrize("tid", [t.id for t in ENGINE.templates])
def test_every_template_renders(tid):
    r = ENGINE.render(tid)
    assert "{{" not in r.spl and "{{" not in r.kuma
    assert r.kuma.lstrip().upper().startswith("SELECT") and "FROM `events`" in r.kuma
    assert "LIMIT 250" in r.kuma


def test_enough_templates_and_categories():
    assert len(ENGINE.templates) >= 30
    assert {"Аутентификация", "Процессы", "Сеть", "Почта"} <= set(ENGINE.categories())


def test_escaping():
    assert esc_spl('a"b\\c') == 'a\\"b\\\\c'
    assert esc_sql("o'brien") == "o\\'brien"
    assert like("adm*_x%") == "adm%\\_x\\%"
    assert like("") == "%"


def test_injection_is_neutralised():
    r = ENGINE.render("by_user", {"user": "x' OR 1=1 --"})
    assert "ILIKE 'x\\' OR 1=1 --'" in r.kuma


def test_env_and_int_params():
    r = ENGINE.render("bruteforce", {"threshold": "abc"}, {"earliest": "-7d", "win_index": "win"})
    assert "index=win" in r.spl and "earliest=-7d" in r.spl
    assert "failures >= 10" in r.spl  # нечисловой порог заменён значением по умолчанию


def test_custom_templates_override(tmp_path):
    (tmp_path / "my.yaml").write_text(
        "- id: bruteforce\n  title: Мой брутфорс\n  category: Своё\n  spl: index=x\n  kuma: SELECT 1 FROM `events`\n",
        encoding="utf-8")
    e = QueryEngine(QuerySettings(custom_templates_dir=str(tmp_path)))
    assert e.by_id["bruteforce"].title == "Мой брутфорс" and e.by_id["bruteforce"].source == "my.yaml"


def test_broken_custom_template_is_skipped(tmp_path):
    (tmp_path / "bad.yaml").write_text("- id: bad\n  title: x\n  spl: '{{ unclosed'\n  kuma: x\n", encoding="utf-8")
    e = QueryEngine(QuerySettings(custom_templates_dir=str(tmp_path)))
    assert "bad" not in e.by_id


def test_suggest():
    ids = ENGINE.suggest({"user": "ivan", "ip": "1.2.3.4", "host": "", "domain": "", "hash": "", "process": ""})
    assert "by_user" in ids and "by_ip" in ids and "by_host" not in ids
