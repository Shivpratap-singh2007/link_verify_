from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.core.config import Settings
from app.security.ssrf import SafeFetchResult
from app.services.threat_intel.base import threat_intel_cache
from app.services.threat_intel.google_safe_browsing import GoogleSafeBrowsingProvider
from app.services.threat_intel.orchestrator import ThreatIntelOrchestrator
from app.services.threat_intel.urlhaus import URLhausProvider
from app.services.threat_intel.virustotal import VirusTotalProvider
from app.services.url_parser import parse_url


@pytest.mark.anyio
async def test_unconfigured_providers_return_explicit_not_configured_message():
    settings = Settings(
        google_safe_browsing_api_key="",
        virustotal_api_key="",
        phishtank_api_key="",
        urlhaus_auth_key="",
    )
    orchestrator = ThreatIntelOrchestrator(settings)
    parsed = parse_url("https://example.com")
    results = await orchestrator.evaluate("https://example.com", parsed)

    assert len(results) == 4
    for r in results:
        assert r.detection_status == "not_configured"
        assert r.message == "Threat intelligence service not configured."


@pytest.mark.anyio
async def test_private_ip_skips_external_threat_intel():
    settings = Settings(google_safe_browsing_api_key="dummy-key")
    orchestrator = ThreatIntelOrchestrator(settings)
    parsed = parse_url("http://192.168.1.1/login/verify")
    results = await orchestrator.evaluate("http://192.168.1.1/login/verify", parsed)

    assert all(r.detection_status == "unavailable" for r in results)
    assert all("private" in r.message.lower() for r in results)


@pytest.mark.anyio
async def test_provider_handles_timeout_and_rate_limit_gracefully():
    settings = Settings(virustotal_api_key="vt-key", urlhaus_auth_key="uh-key")

    vt = VirusTotalProvider(settings)
    with patch(
        "app.services.threat_intel.virustotal.safe_fetch_external_api",
        new=AsyncMock(side_effect=httpx.ReadTimeout("timed out")),
    ):
        vt_res = await vt.lookup("https://example.com")
    assert vt_res.detection_status == "unavailable"
    assert "timed out" in vt_res.message.lower()

    uh = URLhausProvider(settings)
    with patch(
        "app.services.threat_intel.urlhaus.safe_fetch_external_api",
        new=AsyncMock(return_value=SafeFetchResult("https://urlhaus-api.abuse.ch/v1/url/", 429, b"{}", "application/json")),
    ):
        uh_res = await uh.lookup("https://example.com")
    assert uh_res.detection_status == "rate_limited"


@pytest.mark.anyio
async def test_orchestrator_caches_repeated_provider_lookups():
    threat_intel_cache.clear()
    settings = Settings(google_safe_browsing_api_key="gsb-key")
    orchestrator = ThreatIntelOrchestrator(settings)
    parsed = parse_url("https://example.com")

    mock_fetch = AsyncMock(
        return_value=SafeFetchResult(
            GoogleSafeBrowsingProvider.ENDPOINT,
            200,
            b"{}",
            "application/json",
        )
    )
    with patch("app.services.threat_intel.google_safe_browsing.safe_fetch_external_api", new=mock_fetch):
        first = await orchestrator.evaluate("https://example.com", parsed)
        second = await orchestrator.evaluate("https://example.com", parsed)

    assert mock_fetch.await_count == 1
    gsb_first = next(r for r in first if r.provider == "google_safe_browsing")
    gsb_second = next(r for r in second if r.provider == "google_safe_browsing")
    assert gsb_first.cached is False
    assert gsb_second.cached is True

