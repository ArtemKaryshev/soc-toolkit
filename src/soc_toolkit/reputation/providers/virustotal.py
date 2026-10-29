from __future__ import annotations

import base64
from datetime import UTC, datetime

from ...ioc import IOCType
from ..base import Provider, ProviderError, RepResult, Verdict

_PATHS = {IOCType.IPV4: "ip_addresses", IOCType.IPV6: "ip_addresses", IOCType.DOMAIN: "domains",
          IOCType.URL: "urls", IOCType.MD5: "files", IOCType.SHA1: "files", IOCType.SHA256: "files"}
_GUI = {"ip_addresses": "ip-address", "domains": "domain", "urls": "url", "files": "file"}


class VirusTotal(Provider):
    name = "virustotal"
    title = "VirusTotal"
    supported = frozenset(_PATHS)
    signup_url = "https://www.virustotal.com/gui/my-apikey"

    def check(self, ioc_type: IOCType, value: str) -> RepResult:
        path = _PATHS[ioc_type]
        ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") if ioc_type == IOCType.URL else value
        link = f"https://www.virustotal.com/gui/{_GUI[path]}/{ident}"
        r = self._get(f"https://www.virustotal.com/api/v3/{path}/{ident}", headers={"x-apikey": self.api_key})
        if r.status_code == 404:
            return self.result(ioc_type, value, Verdict.UNKNOWN, summary="нет данных в VirusTotal", link=link)
        if not r.ok:
            raise ProviderError(f"HTTP {r.status_code}")
        a = r.json()["data"]["attributes"]
        stats = a.get("last_analysis_stats", {})
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int))
        verdict = Verdict.MALICIOUS if mal >= 3 else Verdict.SUSPICIOUS if (mal or sus) else Verdict.CLEAN
        details = {
            "malicious": mal, "suspicious": sus, "total_engines": total,
            "reputation": a.get("reputation"),
            "country": a.get("country"), "as_owner": a.get("as_owner"), "asn": a.get("asn"),
            "registrar": a.get("registrar"),
            "creation_date": _ts(a.get("creation_date")),
            "last_analysis": _ts(a.get("last_analysis_date")),
            "names": a.get("names", [])[:5], "type": a.get("type_description"),
            "threat_label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label"),
            "tags": a.get("tags", [])[:10],
        }
        details = {k: v for k, v in details.items() if v not in (None, "", [])}
        bits = [f"{mal}/{total} движков"]
        for key, label in (("threat_label", "семейство"), ("as_owner", "AS"), ("country", "страна"),
                           ("creation_date", "домен создан"), ("type", "тип")):
            if key in details:
                bits.append(f"{label}: {details[key]}")
        return self.result(ioc_type, value, verdict, score=f"{mal}/{total}", details=details,
                           summary="; ".join(bits), link=link)


def _ts(v: int | None) -> str | None:
    return datetime.fromtimestamp(v, UTC).strftime("%Y-%m-%d") if v else None
