import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Optional, Set
from urllib.parse import urljoin, urlsplit

import httpx


class URLValidationError(ValueError):
    """Raised when a submitted URL fails syntactic or safety validation."""

    def __init__(self, message: str, code: str = "INVALID_URL") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class SSRFBlockedError(URLValidationError):
    """Raised when a URL targets a restricted internal, loopback, or metadata resource."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="SSRF_BLOCKED")


CLOUD_METADATA_HOSTS: Set[str] = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "100.100.100.200",
    "fd00:ec2::254",
}

LOCAL_HOSTNAMES: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}


def _strip_ipv6_brackets(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def parse_ip_literal(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse standard or integer/hex IPv4/IPv6 host literals if applicable."""
    cleaned = _strip_ipv6_brackets(host.strip())
    if not cleaned:
        return None
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass
    # Handle single-integer decimal or hex IPv4 representations (e.g. 2130706433 or 0x7f000001)
    if cleaned.isdigit():
        try:
            val = int(cleaned, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            return None
    if cleaned.lower().startswith("0x"):
        try:
            val = int(cleaned, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            return None
    return None


def is_restricted_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if IP is non-public (private, loopback, link-local, reserved, multicast, etc.)."""
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or not ip_obj.is_global
    )


def validate_submitted_url(raw_url: str) -> str:
    """Validate and normalize a user-submitted URL for static inspection.

    Static analysis never connects to or executes the target URL.
    Still blocks non-HTTP(S) schemes, malformed input, loopback/localhost,
    link-local ranges, and cloud metadata endpoints.
    """
    if not isinstance(raw_url, str):
        raise URLValidationError("URL must be a string.")

    url = raw_url.strip()
    if not url:
        raise URLValidationError("URL cannot be empty.")
    if len(url) > 2048:
        raise URLValidationError("URL exceeds maximum allowed length of 2048 characters.")

    if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise URLValidationError("URL contains invalid control characters.")
    if any(ch.isspace() for ch in url):
        raise URLValidationError("URL cannot contain whitespace characters.")

    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise URLValidationError(f"Malformed URL: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise URLValidationError(
            "Only HTTP and HTTPS URLs are supported.",
            code="UNSUPPORTED_SCHEME",
        )

    if not parsed.netloc or not parsed.hostname:
        raise URLValidationError("URL must include a valid host or domain name.")

    try:
        _ = parsed.port
    except ValueError as exc:
        raise URLValidationError("URL contains an invalid port number.") from exc

    host = _strip_ipv6_brackets(parsed.hostname).lower().rstrip(".")
    if not host:
        raise URLValidationError("URL host cannot be empty.")

    if host in CLOUD_METADATA_HOSTS or host.endswith(".internal"):
        raise SSRFBlockedError("Cloud metadata and internal hostnames are blocked.")

    if host in LOCAL_HOSTNAMES or host.endswith(".localhost") or host.endswith(".local"):
        raise SSRFBlockedError("Localhost and local network hostnames are blocked.")

    ip_obj = parse_ip_literal(host)
    if ip_obj is not None:
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            ip_obj = ip_obj.ipv4_mapped
        if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_multicast:
            raise SSRFBlockedError("Loopback, link-local, unspecified, and multicast IPs are blocked.")

    return url


def validate_fetch_target(
    url: str,
    resolver: Optional[Callable[[str], list[str]]] = None,
) -> str:
    """Strict SSRF guard for any server-side outbound HTTP request.

    Blocks ALL private IPv4/IPv6 ranges, loopback, link-local, cloud metadata,
    localhost, and DNS resolutions pointing to restricted IPs (DNS rebinding guard).
    """
    validated = validate_submitted_url(url)
    parsed = urlsplit(validated)
    host = _strip_ipv6_brackets(parsed.hostname or "").lower().rstrip(".")

    ip_obj = parse_ip_literal(host)
    if ip_obj is not None:
        if is_restricted_ip(ip_obj):
            raise SSRFBlockedError(f"Target IP {ip_obj} is in a restricted or private range.")
        return validated

    # Resolve host DNS to defend against DNS rebinding to internal IPs
    if resolver is not None:
        resolved_ips = resolver(host)
    else:
        try:
            addr_infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
            resolved_ips = [info[4][0] for info in addr_infos]
        except socket.gaierror as exc:
            raise URLValidationError(f"Unable to resolve target host: {host}", code="DNS_RESOLUTION_FAILED") from exc

    if not resolved_ips:
        raise URLValidationError(f"No DNS records found for host: {host}", code="DNS_RESOLUTION_FAILED")

    for ip_str in resolved_ips:
        resolved_ip = parse_ip_literal(ip_str)
        if resolved_ip is None or is_restricted_ip(resolved_ip):
            raise SSRFBlockedError(
                f"Resolved address {ip_str} for host {host} is restricted (SSRF/DNS rebinding protection)."
            )

    return validated


@dataclass
class SafeFetchResult:
    final_url: str
    status_code: int
    body: bytes
    content_type: str


async def safe_fetch_external_api(
    url: str,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    json_body: Optional[dict] = None,
    data_body: Optional[dict] = None,
    params: Optional[dict] = None,
    timeout_seconds: float = 4.0,
    max_bytes: int = 1_048_576,
    max_redirects: int = 2,
    client: Optional[httpx.AsyncClient] = None,
) -> SafeFetchResult:
    """Perform an SSRF-safe outbound HTTP request (used strictly for trusted threat-intel APIs).

    Validates initial URL and every redirect hop, disables automatic redirects,
    enforces timeouts and maximum response byte size.
    """
    current_url = validate_fetch_target(url)
    owns_client = client is None
    active_client = client or httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False)

    try:
        for _ in range(max_redirects + 1):
            async with active_client.stream(
                method=method,
                url=current_url,
                headers=headers,
                json=json_body,
                data=data_body,
                params=params,
                timeout=timeout_seconds,
            ) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise URLValidationError("Redirect response missing Location header.")
                    next_url = urljoin(current_url, location)
                    current_url = validate_fetch_target(next_url)
                    method = "GET" if response.status_code in {301, 302, 303} else method
                    json_body = None if method == "GET" else json_body
                    data_body = None if method == "GET" else data_body
                    continue

                chunks = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise URLValidationError(
                            f"Response exceeded maximum limit of {max_bytes} bytes.",
                            code="RESPONSE_TOO_LARGE",
                        )
                    chunks.append(chunk)

                return SafeFetchResult(
                    final_url=current_url,
                    status_code=response.status_code,
                    body=b"".join(chunks),
                    content_type=response.headers.get("content-type", ""),
                )
        raise URLValidationError("Exceeded maximum allowed redirects.", code="TOO_MANY_REDIRECTS")
    finally:
        if owns_client:
            await active_client.aclose()

