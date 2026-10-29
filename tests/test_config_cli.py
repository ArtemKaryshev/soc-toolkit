import json

import pytest
from typer.testing import CliRunner

from soc_toolkit.cli import app
from soc_toolkit.config import load_settings

runner = CliRunner()


def test_settings_defaults_and_file(tmp_path, monkeypatch):
    s = load_settings()
    assert s.source is None and s.queries.win_index == "wineventlog"
    cfg = tmp_path / "config.toml"
    cfg.write_text('[api_keys]\nvirustotal = "abc"\n[queries]\nwin_index = "win"\n'
                   '[reputation.rate_limits]\nvirustotal = 1\n', encoding="utf-8")
    monkeypatch.setenv("OTX_API_KEY", "envkey")
    s = load_settings(cfg)
    assert s.api_keys == {"virustotal": "abc", "otx": "envkey"}
    assert s.queries.win_index == "win"
    assert s.reputation.rate_limits["virustotal"] == 1 and s.reputation.rate_limits["abuseipdb"] == 30


def test_cli_version():
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0 and "soc-toolkit" in r.stdout


def test_cli_ioc_extract_json(samples):
    r = runner.invoke(app, ["ioc", "extract", str(samples / "phishing_email.txt"), "-f", "json", "--external"])
    assert r.exit_code == 0
    vals = {x["value"] for x in json.loads(r.stdout)}
    assert "185.220.101.45" in vals and "10.10.5.20" not in vals


def test_cli_defang_refang():
    assert runner.invoke(app, ["ioc", "defang", "http://evil.com"]).stdout.strip() == "hxxp[://]evil[.]com"
    assert runner.invoke(app, ["ioc", "refang", "evil[.]com"]).stdout.strip() == "evil.com"


def test_cli_report_and_cases(samples, tmp_path):
    out = tmp_path / "r.md"
    r = runner.invoke(app, ["report", str(samples / "alert_kuma.json"), "-v", "TP", "-c", "bruteforce",
                            "-o", str(out), "--save-case"])
    assert r.exit_code == 0, r.stdout
    assert "Recommended Remediation Actions" in out.read_text(encoding="utf-8")
    r = runner.invoke(app, ["cases", "list"])
    assert "Brute" in r.stdout
    r = runner.invoke(app, ["report", str(samples / "alert_kuma.json"), "-c", "nope"])
    assert r.exit_code == 2


def test_cli_query_from_alert(samples):
    r = runner.invoke(app, ["query", "render", "by_user", "--from-alert", str(samples / "alert_splunk.json"),
                            "--target", "kuma"])
    assert r.exit_code == 0 and "ivan.petrov" in r.stdout


def test_cli_rep_requires_policy():
    r = runner.invoke(app, ["rep", "check", "1.2.3.4"])
    assert r.exit_code == 3


def test_cli_ref():
    assert "Kerberoasting" in runner.invoke(app, ["ref", "event", "4769"]).stdout
    assert "T1003.001" in runner.invoke(app, ["ref", "mitre", "lsass"]).stdout


def test_broken_config_explained(tmp_path):
    from soc_toolkit.config import ConfigError, load_settings

    cfg = tmp_path / "config.toml"
    cfg.write_text('[api_keys]\nvirustotal = ""\nabuseipdb = "abc\n', encoding="utf-8")
    with pytest.raises(ConfigError) as e:
        load_settings(cfg)
    text = str(e.value)
    assert "Строка 3, параметр «abuseipdb»" in text and "закрывающей кавычки" in text
    assert "abc" not in text


def test_broken_config_cli(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text('log_level = "INFO\n', encoding="utf-8")
    monkeypatch.setenv("SOC_TOOLKIT_CONFIG", str(cfg))
    result = CliRunner().invoke(app, ["info"])
    assert result.exit_code == 2
    assert "Traceback" not in result.output
