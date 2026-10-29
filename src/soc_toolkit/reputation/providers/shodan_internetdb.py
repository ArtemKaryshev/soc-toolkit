from __future__ import annotations

from ...ioc import IOCType
from ..base import Provider, ProviderError, RepResult, Verdict


class ShodanInternetDB(Provider):
    """Бесплатный InternetDB от Shodan без ключа: открытые порты, уязвимости, теги хоста."""

    name = "shodan_internetdb"
    title = "Shodan InternetDB"
    supported = frozenset({IOCType.IPV4})
    requires_key = False
    signup_url = "https://internetdb.shodan.io/"

    def check(self, ioc_type: IOCType, value: str) -> RepResult:
        r = self._get(f"https://internetdb.shodan.io/{value}")
        link = f"https://www.shodan.io/host/{value}"
        if r.status_code == 404:
            return self.result(ioc_type, value, Verdict.UNKNOWN, summary="нет данных", link=link)
        if not r.ok:
            raise ProviderError(f"HTTP {r.status_code}")
        d = r.json()
        tags = d.get("tags", [])
        bad = {"malware", "c2", "compromised", "tor", "honeypot", "scanner"} & set(tags)
        verdict = Verdict.SUSPICIOUS if bad else Verdict.UNKNOWN
        bits = []
        if d.get("ports"):
            bits.append("порты: " + ", ".join(map(str, d["ports"][:15])))
        if tags:
            bits.append("теги: " + ", ".join(tags))
        if d.get("vulns"):
            bits.append(f"CVE: {len(d['vulns'])}")
        if d.get("hostnames"):
            bits.append("имена: " + ", ".join(d["hostnames"][:3]))
        details = {k: d.get(k) for k in ("ports", "tags", "vulns", "hostnames", "cpes")}
        return self.result(ioc_type, value, verdict, score=f"{len(d.get('ports', []))} портов", details=details,
                           summary="; ".join(bits) or "открытых портов нет", link=link)
