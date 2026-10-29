from __future__ import annotations

from ...ioc import IOCType
from ..base import Provider, ProviderError, RepResult, Verdict


class GreyNoise(Provider):
    """GreyNoise Community API: отличает массовые сканеры интернета и легитимные сервисы от целевых атак."""

    name = "greynoise"
    title = "GreyNoise Community"
    supported = frozenset({IOCType.IPV4})
    requires_key = False
    signup_url = "https://viz.greynoise.io/signup"

    def check(self, ioc_type: IOCType, value: str) -> RepResult:
        headers = {"key": self.api_key} if self.api_key else {}
        r = self._get(f"https://api.greynoise.io/v3/community/{value}", headers=headers)
        link = f"https://viz.greynoise.io/ip/{value}"
        if r.status_code == 404:
            return self.result(ioc_type, value, Verdict.UNKNOWN, summary="не замечен в массовом сканировании",
                               link=link)
        if not r.ok:
            raise ProviderError(f"HTTP {r.status_code}")
        d = r.json()
        cls = d.get("classification", "unknown")
        verdict = {"malicious": Verdict.MALICIOUS, "benign": Verdict.CLEAN}.get(cls, Verdict.SUSPICIOUS
                                                                               if d.get("noise") else Verdict.UNKNOWN)
        bits = [f"класс: {cls}"]
        if d.get("noise"):
            bits.append("массовый сканер")
        if d.get("riot"):
            bits.append("известный легитимный сервис (RIOT)")
        if d.get("name") and d["name"] != "unknown":
            bits.append(f"имя: {d['name']}")
        details = {k: d.get(k) for k in ("noise", "riot", "classification", "name", "last_seen")}
        return self.result(ioc_type, value, verdict, score=cls, details=details, summary="; ".join(bits), link=link)
