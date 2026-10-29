from __future__ import annotations

from ...ioc import IOCType
from ..base import Provider, ProviderError, RepResult, Verdict


class AbuseIPDB(Provider):
    name = "abuseipdb"
    title = "AbuseIPDB"
    supported = frozenset({IOCType.IPV4, IOCType.IPV6})
    signup_url = "https://www.abuseipdb.com/account/api"

    def check(self, ioc_type: IOCType, value: str) -> RepResult:
        r = self._get("https://api.abuseipdb.com/api/v2/check",
                      params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
                      headers={"Key": self.api_key, "Accept": "application/json"})
        if not r.ok:
            raise ProviderError(f"HTTP {r.status_code}")
        d = r.json()["data"]
        conf = int(d.get("abuseConfidenceScore") or 0)
        reports = int(d.get("totalReports") or 0)
        verdict = (Verdict.MALICIOUS if conf >= 50 else Verdict.SUSPICIOUS if conf > 0 or reports
                   else Verdict.CLEAN)
        details = {k: d.get(k) for k in ("abuseConfidenceScore", "totalReports", "numDistinctUsers", "countryCode",
                                         "isp", "domain", "usageType", "isTor", "isWhitelisted", "lastReportedAt")}
        bits = [f"уверенность {conf}%", f"жалоб: {reports}"]
        if d.get("isTor"):
            bits.append("узел Tor")
        bits += [f"{k}: {d[k]}" for k in ("countryCode", "isp", "usageType") if d.get(k)]
        return self.result(ioc_type, value, verdict, score=f"{conf}%", details=details, summary="; ".join(bits),
                           link=f"https://www.abuseipdb.com/check/{value}")
