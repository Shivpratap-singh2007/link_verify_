import asyncio
from typing import List, Optional

from app.core.config import Settings, get_settings
from app.services.threat_intel.base import ThreatIntelResult, threat_intel_cache
from app.services.threat_intel.google_safe_browsing import GoogleSafeBrowsingProvider
from app.services.threat_intel.phishtank import PhishTankProvider
from app.services.threat_intel.urlhaus import URLhausProvider
from app.services.threat_intel.virustotal import VirusTotalProvider
from app.services.url_parser import ParsedURL


class ThreatIntelOrchestrator:
    """Runs configured threat intelligence lookups concurrently with TTL caching and graceful degradation."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self.providers = [
            GoogleSafeBrowsingProvider(self.settings),
            VirusTotalProvider(self.settings),
            PhishTankProvider(self.settings),
            URLhausProvider(self.settings),
        ]

    async def evaluate(self, url: str, parsed: ParsedURL) -> List[ThreatIntelResult]:
        if parsed.is_private_ip:
            return [
                ThreatIntelResult(
                    provider=provider.name,
                    detection_status="unavailable",
                    message="External threat intelligence skipped for private/non-routable IP address.",
                    details={"skipped_private_ip": True},
                )
                for provider in self.providers
            ]

        async def _check_one(provider) -> ThreatIntelResult:
            cached = threat_intel_cache.get(provider.name, url)
            if cached is not None:
                return cached
            result = await provider.lookup(url)
            # Only cache definitive or unconfigured responses briefly; skip caching transient errors
            if result.detection_status in {"clean", "malicious", "suspicious"}:
                threat_intel_cache.set(
                    provider.name,
                    url,
                    result,
                    self.settings.threat_intel_cache_ttl_seconds,
                )
            return result

        return list(await asyncio.gather(*[_check_one(p) for p in self.providers]))
