import json
import httpx

from app.core.config import Settings
from app.security.ssrf import safe_fetch_external_api
from app.services.threat_intel.base import ThreatIntelResult


class PhishTankProvider:
    name = "phishtank"
    ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.phishtank_api_key.strip()
        self.timeout = settings.threat_intel_timeout_seconds

    async def lookup(self, url: str) -> ThreatIntelResult:
        if not self.api_key:
            return ThreatIntelResult(
                provider=self.name,
                detection_status="not_configured",
                message="Threat intelligence service not configured.",
                details={"configured": False},
            )

        form_data = {"url": url, "format": "json", "app_key": self.api_key}
        try:
            resp = await safe_fetch_external_api(
                url=self.ENDPOINT,
                method="POST",
                headers={"User-Agent": "phishtank/link-verify-ai"},
                data_body=form_data,
                timeout_seconds=self.timeout,
            )
            if resp.status_code == 429:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="rate_limited",
                    message="PhishTank API rate limit exceeded.",
                    details={"status_code": 429},
                )
            if resp.status_code >= 400:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="unavailable",
                    message=f"PhishTank returned HTTP {resp.status_code}.",
                    details={"status_code": resp.status_code},
                )
            data = json.loads(resp.body.decode("utf-8"))
            results = data.get("results", {})
            in_db = bool(results.get("in_database"))
            valid = bool(results.get("valid"))
            if in_db and valid:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="malicious",
                    message="Confirmed phishing URL in PhishTank database.",
                    details={"in_database": True, "valid": True, "phish_id": results.get("phish_id")},
                )
            if in_db:
                return ThreatIntelResult(
                    provider=self.name,
                    detection_status="suspicious",
                    message="URL recorded in PhishTank database (unverified or expired).",
                    details={"in_database": True, "valid": False, "phish_id": results.get("phish_id")},
                )
            return ThreatIntelResult(
                provider=self.name,
                detection_status="clean",
                message="URL not listed in PhishTank database.",
                details={"in_database": False},
            )
        except (httpx.TimeoutException, TimeoutError):
            return ThreatIntelResult(
                provider=self.name,
                detection_status="unavailable",
                message="PhishTank lookup timed out.",
                details={"timeout": True},
            )
        except Exception as exc:
            return ThreatIntelResult(
                provider=self.name,
                detection_status="error",
                message="PhishTank lookup could not be completed.",
                details={"error_type": type(exc).__name__},
            )

