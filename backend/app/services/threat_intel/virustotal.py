import base64
import json
import httpx

from app.core.config import Settings
from app.security.ssrf import safe_fetch_external_api
from app.services.threat_intel.base import ThreatIntelResult


class VirusTotalProvider:
    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3/urls"

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.virustotal_api_key.strip()
        self.timeout = settings.threat_intel_timeout_seconds

    async def lookup(self, url: str) -> ThreatIntelResult:
        if not self.api_key:
            return ThreatIntelResult(
                provider=self.name,
                detection_status="not_configured",
                message="Threat intelligence service not configured.",
                details={"configured": False},
            )

        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        try:
            resp = await safe_fetch_external_api(
                url=f"{self.BASE_URL}/{url_id}",
                method="GET",
                headers={"x-apikey": self.api_key, "Accept": "application/json"},
                timeout_seconds=self.timeout,
            )
            if resp.status_code == 429:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="rate_limited",
                    message="VirusTotal API rate limit exceeded.",
                    details={"status_code": 429},
                )
            if resp.status_code == 404:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="clean",
                    message="URL has no prior malicious report on VirusTotal.",
                    details={"status_code": 404, "malicious": 0, "suspicious": 0},
                )
            if resp.status_code >= 400:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="unavailable",
                    message=f"VirusTotal returned HTTP {resp.status_code}.",
                    details={"status_code": resp.status_code},
                )
            data = json.loads(resp.body.decode("utf-8"))
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            if malicious >= 2:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="malicious",
                    message=f"VirusTotal engines flagged URL ({malicious} malicious, {suspicious} suspicious).",
                    details={"malicious": malicious, "suspicious": suspicious, "harmless": harmless},
                )
            if malicious == 1 or suspicious >= 2:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="suspicious",
                    message=f"VirusTotal reported suspicious engine flags ({malicious} malicious, {suspicious} suspicious).",
                    details={"malicious": malicious, "suspicious": suspicious, "harmless": harmless},
                )
            return ThreatIntelResult(
                provider=self.name,
                detection_status="clean",
                message="No VirusTotal engines flagged this URL.",
                details={"malicious": malicious, "suspicious": suspicious, "harmless": harmless},
            )
        except (httpx.TimeoutException, TimeoutError):
            return ThreatIntelResult(
                provider=self.name,
                detection_status="unavailable",
                message="VirusTotal lookup timed out.",
                details={"timeout": True},
            )
        except Exception as exc:
            return ThreatIntelResult(
                provider=self.name,
                detection_status="error",
                message="VirusTotal lookup could not be completed.",
                details={"error_type": type(exc).__name__},
            )

