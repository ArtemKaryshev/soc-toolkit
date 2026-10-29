from soc_toolkit.ioc import extract, parse_eml, read_text


def test_parse_eml(samples):
    info = parse_eml((samples / "phishing.eml").read_bytes())
    assert info.subject.startswith("Срочно")
    assert info.spf == "fail" and info.dmarc == "fail"
    assert info.attachments[0].filename == "Invoice_2026_10.docm"
    assert len(info.attachments[0].sha256) == 64
    warnings = " ".join(info.warnings)
    assert "Reply-To" in warnings and "SPF" in warnings and "docm" in warnings


def test_eml_text_includes_attachment_strings_and_hashes(samples):
    text, info = read_text("phishing.eml", (samples / "phishing.eml").read_bytes())
    found = extract(text)
    vals = {i.value for i in found}
    assert info.attachments[0].sha256 in vals
    assert "http://45.33.32.156/stage2.ps1" in vals          # из закодированного макроса во вложении
    assert "https://login-micros0ft-helpdesk.com/owa/auth.php?u=ivan.petrov" in vals


def test_html_links_survive_stripping():
    text, _ = read_text("page.html", b'<a href="https://evil.example.com/x">click</a><script>var a=1</script>')
    assert "https://evil.example.com/x" in text and "var a" not in text


def test_json_unicode_escapes():
    text, _ = read_text("a.json", b'{"msg": "\\u0445\\u043e\\u0441\\u0442 evil.com"}')
    assert "хост" in text
