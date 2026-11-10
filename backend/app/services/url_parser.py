from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

import tldextract

from app.security.ssrf import parse_ip_literal, is_restricted_ip

# Strictly offline Public Suffix List extractor — never performs network fetches
_OFFLINE_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)


@dataclass(frozen=True)
class ParsedURL:
    original_url: str
    scheme: str
    username: Optional[str]
    has_at_symbol: bool
    hostname: str
    port: Optional[int]
    registered_domain: str
    subdomain: str
    tld: str
    path: str
    query: str
    fragment: str
    is_ip_literal: bool
    is_private_ip: bool
    is_punycode_or_idn: bool


def parse_url(url: str) -> ParsedURL:
    """Safely parse an HTTP/HTTPS URL without making any network or DNS requests."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    raw_host = (parts.hostname or "").strip().lower().rstrip(".")
    if raw_host.startswith("[") and raw_host.endswith("]"):
        raw_host = raw_host[1:-1]

    # Detect presence of '@' in netloc (authority section) or full URL
    has_at_symbol = "@" in parts.netloc or "@" in url
    username = parts.username

    ip_obj = parse_ip_literal(raw_host)
    is_ip_literal = ip_obj is not None
    is_private_ip = is_restricted_ip(ip_obj) if ip_obj is not None else False

    is_punycode_or_idn = (
        any(label.startswith("xn--") for label in raw_host.split(".") if label)
        or any(ord(ch) > 127 for ch in raw_host)
    )

    if is_ip_literal:
        registered_domain = raw_host
        subdomain = ""
        tld = ""
    else:
        ext = _OFFLINE_EXTRACTOR(raw_host)
        if ext.domain and ext.suffix:
            registered_domain = f"{ext.domain}.{ext.suffix}"
            tld = ext.suffix
        elif ext.domain:
            registered_domain = ext.domain
            tld = ""
        else:
            registered_domain = raw_host
            tld = ""
        subdomain = ext.subdomain or ""

    try:
        port = parts.port
    except ValueError:
        port = None

    return ParsedURL(
        original_url=url,
        scheme=scheme,
        username=username,
        has_at_symbol=has_at_symbol,
        hostname=raw_host,
        port=port,
        registered_domain=registered_domain,
        subdomain=subdomain,
        tld=tld,
        path=parts.path or "",
        query=parts.query or "",
        fragment=parts.fragment or "",
        is_ip_literal=is_ip_literal,
        is_private_ip=is_private_ip,
        is_punycode_or_idn=is_punycode_or_idn,
    )

