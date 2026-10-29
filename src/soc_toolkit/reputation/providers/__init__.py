"""Провайдеры репутации. Чтобы добавить свой, унаследуйте Provider и добавьте класс в PROVIDERS."""

from ..base import Provider
from .abuseipdb import AbuseIPDB
from .greynoise import GreyNoise
from .otx import OTX
from .shodan_internetdb import ShodanInternetDB
from .urlhaus import URLhaus
from .virustotal import VirusTotal

PROVIDERS: dict[str, type[Provider]] = {
    p.name: p for p in (VirusTotal, AbuseIPDB, OTX, GreyNoise, ShodanInternetDB, URLhaus)
}

__all__ = ["OTX", "PROVIDERS", "AbuseIPDB", "GreyNoise", "ShodanInternetDB", "URLhaus", "VirusTotal"]
