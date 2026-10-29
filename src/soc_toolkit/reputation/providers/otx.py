from __future__ import annotations

from ...ioc import IOCType
from ..base import Provider, ProviderError, RepResult, Verdict

_SECTIONS = {IOCType.IPV4: "IPv4", IOCType.IPV6: "IPv6", IOCType.DOMAIN: "domain", IOCType.URL: "url",
             IOCType.MD5: "file", IOCType.SHA1: "file", IOCType.SHA256: "file"}


class OTX(Provider):
    name = "otx"
    title = "AlienVault OTX"
    supported = frozenset(_SECTIONS)
    signup_url = "https://otx.alienvault.com/api"

    def check(self, ioc_type: IOCType, value: str) -> RepResult:
        section = _SECTIONS[ioc_type]
        r = self._get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
                      headers={"X-OTX-API-KEY": self.api_key})
        gui = "file" if section == "file" else section.lower()
        link = f"https://otx.alienvault.com/indicator/{gui}/{value}"
        if r.status_code in (400, 404):
            return self.result(ioc_type, value, Verdict.UNKNOWN, summary="нет данных в OTX", link=link)
        if not r.ok:
            raise ProviderError(f"HTTP {r.status_code}")
        info = r.json().get("pulse_info", {})
        count = int(info.get("count") or 0)
        pulses = info.get("pulses", [])
        families = sorted({m.get("display_name", "") for p in pulses for m in p.get("malware_families", [])} - {""})
        adversaries = sorted({p.get("adversary", "") for p in pulses} - {""})
        verdict = Verdict.MALICIOUS if count >= 5 else Verdict.SUSPICIOUS if count else Verdict.CLEAN
        details = {"pulses": count, "pulse_names": [p.get("name") for p in pulses[:5]],
                   "malware_families": families[:10], "adversaries": adversaries[:5]}
        bits = [f"pulses: {count}"]
        if families:
            bits.append("семейства: " + ", ".join(families[:5]))
        if adversaries:
            bits.append("группировки: " + ", ".join(adversaries[:3]))
        return self.result(ioc_type, value, verdict, score=f"{count} pulses", details=details,
                           summary="; ".join(bits), link=link)
