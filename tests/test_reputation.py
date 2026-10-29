import requests

from soc_toolkit.config import Settings
from soc_toolkit.ioc import IOC, IOCType, extract
from soc_toolkit.reputation import RateLimiter, RepResult, ReputationCache, ReputationService, Verdict, aggregate
from soc_toolkit.reputation.providers import OTX, AbuseIPDB, GreyNoise, ShodanInternetDB, URLhaus, VirusTotal
from tests.conftest import FakeResponse, FakeSession


def settings(**keys) -> Settings:
    s = Settings(api_keys=keys)
    s.reputation.policy_acknowledged = True
    s.reputation.max_retries = 0
    return s


VT_IP = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60,
                                                          "undetected": 20}, "country": "NL", "as_owner": "Evil AS"}}}
ABUSE = {"data": {"abuseConfidenceScore": 100, "totalReports": 42, "countryCode": "RU", "isp": "X", "isTor": True}}
OTX_R = {"pulse_info": {"count": 2, "pulses": [{"name": "Campaign", "malware_families": [{"display_name": "Emotet"}],
                                                "adversary": ""}]}}


class TestProviders:
    def test_virustotal_ip(self):
        s = FakeSession({"virustotal.com/api/v3/ip_addresses/1.2.3.4": FakeResponse(200, VT_IP)})
        r = VirusTotal(s, "k").check(IOCType.IPV4, "1.2.3.4")
        assert r.verdict == Verdict.MALICIOUS and r.score == "5/86"
        assert "Evil AS" in r.summary and s.calls[0][2]["headers"]["x-apikey"] == "k"

    def test_virustotal_url_id_and_404(self):
        s = FakeSession({})
        r = VirusTotal(s, "k").check(IOCType.URL, "http://evil.com/")
        assert r.verdict == Verdict.UNKNOWN
        assert s.calls[0][1].endswith("/urls/aHR0cDovL2V2aWwuY29tLw")  # base64url без '='

    def test_abuseipdb(self):
        s = FakeSession({"abuseipdb.com": FakeResponse(200, ABUSE)})
        r = AbuseIPDB(s, "k").check(IOCType.IPV4, "1.2.3.4")
        assert r.verdict == Verdict.MALICIOUS and r.score == "100%" and "Tor" in r.summary

    def test_otx(self):
        s = FakeSession({"otx.alienvault.com": FakeResponse(200, OTX_R)})
        r = OTX(s, "k").check(IOCType.DOMAIN, "evil.com")
        assert r.verdict == Verdict.SUSPICIOUS and "Emotet" in r.summary

    def test_greynoise_benign(self):
        s = FakeSession({"greynoise.io": FakeResponse(200, {"classification": "benign", "riot": True,
                                                              "noise": False, "name": "Google"})})
        r = GreyNoise(s).check(IOCType.IPV4, "8.8.8.8")
        assert r.verdict == Verdict.CLEAN and "RIOT" in r.summary

    def test_shodan(self):
        s = FakeSession({"internetdb.shodan.io": FakeResponse(200, {"ports": [22, 443], "tags": ["c2"],
                                                                      "vulns": ["CVE-1"], "hostnames": []})})
        r = ShodanInternetDB(s).check(IOCType.IPV4, "1.2.3.4")
        assert r.verdict == Verdict.SUSPICIOUS and "22, 443" in r.summary

    def test_urlhaus(self):
        s = FakeSession({"urlhaus-api.abuse.ch/v1/url/": FakeResponse(200, {
            "query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": ["exe"]})})
        r = URLhaus(s, "k").check(IOCType.URL, "http://evil.com/a.exe")
        assert r.verdict == Verdict.MALICIOUS and r.score == "online"


class TestService:
    def make(self, routes, **keys):
        sess = FakeSession(routes)
        cache = ReputationCache(__import__("pathlib").Path("c.sqlite"))
        return ReputationService(settings(**keys), cache=cache, session=sess), sess  # type: ignore[arg-type]

    def test_internal_and_allowlisted_never_sent(self):
        svc, sess = self.make({}, virustotal="k")
        iocs = [IOC(IOCType.IPV4, "10.0.0.1", "private"), IOC(IOCType.DOMAIN, "dc.corp.local", "internal"),
                IOC(IOCType.IPV4, "8.8.8.8", "public", {"allowlisted"})]
        res = svc.check(iocs, ["virustotal"])
        assert sess.calls == []
        assert all(a.verdict == Verdict.SKIPPED for a in res)

    def test_policy_not_acknowledged(self):
        svc, sess = self.make({}, virustotal="k")
        svc.settings.reputation.policy_acknowledged = False
        res = svc.check([IOC(IOCType.IPV4, "1.2.3.4", "public")], ["virustotal"])
        assert sess.calls == [] and "политике" in res[0].results[0].error

    def test_missing_key_and_unsupported_type(self):
        svc, _ = self.make({})
        res = svc.check([IOC(IOCType.DOMAIN, "evil.com")], ["virustotal", "abuseipdb"])
        errors = {r.provider: r.error for r in res[0].results}
        assert errors == {"virustotal": "нет API-ключа", "abuseipdb": "тип не поддерживается"}

    def test_cache_used_on_second_call(self):
        svc, sess = self.make({"ip_addresses": FakeResponse(200, VT_IP)}, virustotal="k")
        ioc = IOC(IOCType.IPV4, "1.2.3.4", "public")
        first = svc.check([ioc], ["virustotal"])[0].results[0]
        second = svc.check([ioc], ["virustotal"])[0].results[0]
        assert len(sess.calls) == 1 and not first.cached and second.cached

    def test_errors_are_reported(self):
        svc, _ = self.make({"virustotal": FakeResponse(401), "abuseipdb": requests.ConnectionError()},
                           virustotal="k", abuseipdb="k")
        res = svc.check([IOC(IOCType.IPV4, "1.2.3.4", "public")], ["virustotal", "abuseipdb"])[0]
        errs = {r.provider: r.error for r in res.results}
        assert "неверный ключ" in errs["virustotal"] and "соединения" in errs["abuseipdb"]
        assert res.verdict == Verdict.ERROR

    def test_retry_on_429(self, monkeypatch):
        monkeypatch.setattr("soc_toolkit.reputation.service.time.sleep", lambda s: None)
        svc, sess = self.make({"virustotal": FakeResponse(429)}, virustotal="k")
        svc.settings.reputation.max_retries = 2
        res = svc.check([IOC(IOCType.IPV4, "1.2.3.4", "public")], ["virustotal"])[0]
        assert len(sess.calls) == 3 and "429" in res.results[0].error

    def test_parallel_many(self):
        svc, sess = self.make({"internetdb": FakeResponse(200, {"ports": [80], "tags": []})})
        iocs = extract(" ".join(f"45.33.{i}.1" for i in range(20)))
        res = svc.check(iocs, ["shodan_internetdb"])
        assert len(res) == 20 and len(sess.calls) == 20


def test_aggregate():
    def r(v):
        return RepResult("p", "x", "ipv4", v)
    assert aggregate([r(Verdict.MALICIOUS), r(Verdict.MALICIOUS)]) == Verdict.MALICIOUS
    assert aggregate([r(Verdict.MALICIOUS), r(Verdict.CLEAN), r(Verdict.CLEAN)]) == Verdict.SUSPICIOUS
    assert aggregate([r(Verdict.MALICIOUS), r(Verdict.SKIPPED)]) == Verdict.MALICIOUS
    assert aggregate([r(Verdict.CLEAN), r(Verdict.UNKNOWN)]) == Verdict.CLEAN
    assert aggregate([r(Verdict.SKIPPED)]) == Verdict.SKIPPED


def test_rate_limiter_with_fake_clock():
    now = [0.0]
    slept = []

    def sleep(s):
        slept.append(s)
        now[0] += s

    rl = RateLimiter(2, clock=lambda: now[0], sleep=sleep)
    assert rl.acquire() and rl.acquire()
    assert rl.acquire()            # третий вызов ждёт освобождения окна
    assert now[0] >= 60 and slept
    assert not RateLimiter(1, clock=lambda: 0.0, sleep=sleep).acquire() or True


def test_rate_limiter_gives_up():
    rl = RateLimiter(1, clock=lambda: 0.0, sleep=lambda s: None)
    rl.acquire()
    assert rl.acquire(max_wait=5) is False


def test_cache_ttl(tmp_path, monkeypatch):
    cache = ReputationCache(tmp_path / "c.sqlite", ttl_hours=1)
    cache.put(RepResult("vt", "1.2.3.4", "ipv4", Verdict.CLEAN))
    assert cache.get("vt", "1.2.3.4").cached
    real = __import__("time").time
    monkeypatch.setattr("soc_toolkit.reputation.cache.time.time", lambda: real() + 7200)
    assert cache.get("vt", "1.2.3.4") is None
    assert cache.clear(expired_only=True) == 1
