import json
import httpx

from app.core.config import Settings
from app.security.ssrf import safe_fetch_external_api
from app.services.threat_intel.base import ThreatIntelResult


class URLhausProvider:
    name = "urlhaus"
    ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, settings: Settings) -> None:
        self.auth_key = settings.urlhaus_auth_key.strip()
        self.timeout = settings.threat_intel_timeout_seconds

    async def lookup(self, url: str) -> ThreatIntelResult:
        if not self.auth_key:
            return ThreatIntelResult(
                provider=self.name,
                detection_status="not_configured",
                message="Threat intelligence service not configured.",
                details={"configured": False},
            )

        try:
            resp = await safe_fetch_external_api(
                url=self.ENDPOINT,
                method="POST",
                headers={"Auth-Key": self.auth_key},
                data_body={"url": url},
                timeout_seconds=self.timeout,
            )
            if resp.status_code == 429:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="rate_limited",
                    message="URLhaus API rate limit exceeded.",
                    details={"status_code": 429},
                )
            if resp.status_code >= 400:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="unavailable",
                    message=f"URLhaus returned HTTP {resp.status_code}.",
                    details={"status_code": resp.status_code},
                )
            data = json.loads(resp.body.decode("utf-8"))
            query_status = data.get("query_status")
            if query_status == "ok":
                threat = data.get("threat", "malware_distribution")
                url_status = data.get("url_status", "unknown")
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="malicious",
                    message=f"Matched URLhaus feed (threat: {threat}, status: {url_status}).",
                    details={"query_status": query_status, "threat": threat, "url_status": url_status},
                )
            return ThreatIntelResult(
                provider=self.name,
                detection_status="clean",
                message="URL not found in URLhaus threat feed.",
                details={"query_status": query_status},
            )
        except (httpx.TimeoutException, TimeoutError):
            return ThreatIntelResult(
                provider=self.name,
                detection_status="unavailable",
                message="URLhaus lookup timed out.",
                details={"timeout": True},
            )
        except Exception as exc:
            return ThreatIntelResult(
                provider=self.name,
                detection_status="error",
                message="URLhaus lookup could not be completed.",
                details={"error_type": type(exc).__name__},
            )

