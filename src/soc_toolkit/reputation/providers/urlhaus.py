from __future__ import annotations

from ...ioc import IOCType
from ..base import Provider, ProviderError, RepResult, Verdict


class URLhaus(Provider):
    """abuse.ch URLhaus: URL и хосты, раздающие ВПО, и хэши полезных нагрузок. Нужен бесплатный Auth-Key."""

    name = "urlhaus"
    title = "abuse.ch URLhaus"
    supported = frozenset({IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.MD5, IOCType.SHA256})
    signup_url = "https://auth.abuse.ch/"

    def check(self, ioc_type: IOCType, value: str) -> RepResult:
        base = "https://urlhaus-api.abuse.ch/v1"
        if ioc_type == IOCType.URL:
            endpoint, data = "url/", {"url": value}
        elif ioc_type in (IOCType.DOMAIN, IOCType.IPV4):
            endpoint, data = "host/", {"host": value}
        else:
            endpoint, data = "payload/", {f"{ioc_type.value}_hash": value}
        r = self._request("POST", f"{base}/{endpoint}", data=data, headers={"Auth-Key": self.api_key})
        if not r.ok:
            raise ProviderError(f"HTTP {r.status_code}")
        d = r.json()
        status = d.get("query_status")
        if status in ("no_results", "invalid_url", "invalid_host"):
            return self.result(ioc_type, value, Verdict.UNKNOWN, summary="нет в базе URLhaus")
        if status != "ok":
            raise ProviderError(f"URLhaus: {status}")
        link = d.get("urlhaus_reference", "")
        if endpoint == "url/":
            online = d.get("url_status") == "online"
            threat = d.get("threat", "")
            tags = d.get("tags") or []
            summary = f"статус: {d.get('url_status')}; угроза: {threat}; теги: {', '.join(tags)}"
            return self.result(ioc_type, value, Verdict.MALICIOUS, score="online" if online else "offline",
                               details={"threat": threat, "tags": tags, "status": d.get("url_status")},
                               summary=summary, link=link)
        if endpoint == "host/":
            count = int(d.get("url_count") or 0)
            return self.result(ioc_type, value, Verdict.MALICIOUS if count else Verdict.UNKNOWN,
                               score=f"{count} URL", details={"url_count": count},
                               summary=f"вредоносных URL на хосте: {count}", link=link)
        sig = d.get("signature") or ""
        return self.result(ioc_type, value, Verdict.MALICIOUS, score=sig or "payload",
                           details={"signature": sig, "file_type": d.get("file_type"), "urls": d.get("url_count")},
                           summary=f"полезная нагрузка {d.get('file_type', '')} {sig}".strip(), link=link)
