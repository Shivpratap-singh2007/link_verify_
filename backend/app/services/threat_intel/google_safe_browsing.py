import json
import httpx

from app.core.config import Settings
from app.security.ssrf import safe_fetch_external_api
from app.services.threat_intel.base import ThreatIntelResult


class GoogleSafeBrowsingProvider:
    name = "google_safe_browsing"
    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.google_safe_browsing_api_key.strip()
        self.timeout = settings.threat_intel_timeout_seconds

    async def lookup(self, url: str) -> ThreatIntelResult:
        if not self.api_key:
            return ThreatIntelResult(
                provider=self.name,
                detection_status="not_configured",
                message="Threat intelligence service not configured.",
                details={"configured": False},
            )

        payload = {
            "client": {"clientId": "link-verify-ai", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            resp = await safe_fetch_external_api(
                url=self.ENDPOINT,
                method="POST",
                params={"key": self.api_key},
                json_body=payload,
                timeout_seconds=self.timeout,
            )
            if resp.status_code == 429:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="rate_limited",
                    message="Google Safe Browsing rate limit reached.",
                    details={"status_code": 429},
                )
            if resp.status_code >= 400:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="unavailable",
                    message=f"Google Safe Browsing returned HTTP {resp.status_code}.",
                    details={"status_code": resp.status_code},
                )
            data = json.loads(resp.body.decode("utf-8"))
            matches = data.get("matches", [])
            if matches:
                threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="malicious",
                    message=f"Matched Google Safe Browsing threat list: {', '.join(threat_types)}.",
                    details={"match_count": len(matches), "threat_types": threat_types},
                )
            return ThreatIntelResult(
                provider=self.name,
                detection_status="clean",
                message="No matches found in Google Safe Browsing.",
                details={"match_count": 0},
            )
        except (httpx.TimeoutException, TimeoutError):
            return ThreatIntelResult(
                provider=self.name,
                detection_status="unavailable",
                message="Google Safe Browsing lookup timed out.",
                details={"timeout": True},
            )
        except Exception as exc:
            return ThreatIntelResult(
                provider=self.name,
                detection_status="error",
                message="Google Safe Browsing lookup could not be completed.",
                details={"error_type": type(exc).__name__},
            )

