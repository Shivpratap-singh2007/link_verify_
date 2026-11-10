import pytest

from app.security.ssrf import (
    SSRFBlockedError,
    URLValidationError,
    validate_fetch_target,
    validate_submitted_url,
)


class TestSubmittedURLValidation:
    def test_accepts_valid_http_and_https(self):
        assert validate_submitted_url("https://example.com") == "https://example.com"
        assert validate_submitted_url("http://192.168.1.1/login/verify") == "http://192.168.1.1/login/verify"
        assert validate_submitted_url("https://example.com@evil.example") == "https://example.com@evil.example"
        assert validate_submitted_url("https://example.com/login/verify") == "https://example.com/login/verify"

    @pytest.mark.parametrize(
        "bad_url",
        [
            "",
            "   ",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<script>alert(1)</script>",
            "ftp://example.com/file",
            "https://example.com/has space",
            "https://example.com/\nnewline",
            "not-a-url",
            "http://",
        ],
    )
    def test_rejects_invalid_or_dangerous_schemes(self, bad_url: str):
        with pytest.raises(URLValidationError):
            validate_submitted_url(bad_url)

    @pytest.mark.parametrize(
        "ssrf_url",
        [
            "http://localhost/admin",
            "http://127.0.0.1:8080/secret",
            "http://[::1]/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://2130706433/admin",       # decimal loopback
            "http://0x7f000001/admin",       # hex loopback
        ],
    )
    def test_blocks_loopback_and_cloud_metadata_urls(self, ssrf_url: str):
        with pytest.raises(SSRFBlockedError):
            validate_submitted_url(ssrf_url)


class TestOutboundFetchSSRFGuard:
    @pytest.mark.parametrize(
        "target",
        [
            "http://192.168.1.1/login/verify",
            "http://10.0.0.5/internal",
            "http://172.16.0.1/status",
            "http://127.0.0.1/health",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://[fe80::1]/",
        ],
    )
    def test_fetch_guard_blocks_all_private_and_internal_ips(self, target: str):
        with pytest.raises(SSRFBlockedError):
            validate_fetch_target(target)

    def test_fetch_guard_blocks_dns_rebinding_to_private_ip(self):
        # Simulated DNS resolver returning a private IP for a public-looking hostname
        def rebinding_resolver(_host: str) -> list[str]:
            return ["10.20.30.40"]

        with pytest.raises(SSRFBlockedError):
            validate_fetch_target("https://rebind-attacker.example/api", resolver=rebinding_resolver)

    def test_fetch_guard_allows_public_ip_resolution(self):
        def public_resolver(_host: str) -> list[str]:
            return ["93.184.216.34"]

        assert validate_fetch_target("https://example.com", resolver=public_resolver) == "https://example.com"

