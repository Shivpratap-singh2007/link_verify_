import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Set
from urllib.parse import parse_qsl

from app.services.url_parser import ParsedURL, parse_url

SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "banking",
    "signin",
    "sign-in",
    "wallet",
    "password",
    "credential",
    "reset",
    "suspend",
    "urgent",
    "invoice",
    "unlock",
    "auth",
    "webscr",
    "cmd",
    "recover",
    "billing",
    "security",
    "validation",
)

BRAND_KEYWORDS: tuple[str, ...] = (
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "google",
    "netflix",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
    "linkedin",
    "instagram",
    "facebook",
    "dropbox",
    "dhl",
    "fedex",
    "usps",
    "coinbase",
    "binance",
    "github",
    "office365",
    "outlook",
)

SUSPICIOUS_TLDS: Set[str] = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "xyz",
    "top",
    "zip",
    "mov",
    "click",
    "link",
    "work",
    "support",
    "club",
    "icu",
    "cam",
    "rest",
    "cfd",
    "sbs",
    "buzz",
    "quest",
    "loan",
    "men",
    "date",
    "review",
    "country",
    "stream",
    "download",
    "example",
}

URL_SHORTENERS: Set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "rb.gy",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
}

SPECIAL_CHARS_SET: Set[str] = set("?=&%_!$~*+;,@#")
PERCENT_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")
DOUBLE_ENCODED_RE = re.compile(r"%25[0-9a-fA-F]{2}")
TOKEN_SPLIT_RE = re.compile(r"[^a-zA-Z0-9]+")

FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_subdomains",
    "num_digits",
    "has_ip_address",
    "suspicious_keyword_count",
    "path_length",
    "num_special_chars",
    "has_at_symbol",
    "is_https",
    "has_punycode_idn",
    "has_suspicious_tld",
    "unusual_encoding_count",
    "query_length",
    "num_query_params",
    "url_entropy",
    "domain_entropy",
    "digit_ratio",
    "has_userinfo_domain",
    "domain_hyphen_count",
    "has_non_standard_port",
    "is_url_shortener",
    "brand_in_subdomain_or_path",
)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)


@dataclass
class ExtractedFeatures:
    parsed: ParsedURL
    numeric: Dict[str, float]
    matched_keywords: List[str]
    matched_brands: List[str]
    userinfo_looks_like_domain: bool
    double_encoded_count: int

    def to_feature_vector(self) -> List[float]:
        return [float(self.numeric[name]) for name in FEATURE_NAMES]


def extract_url_features(url: str) -> ExtractedFeatures:
    """Extract deterministic lexical and structural features from a URL without network I/O."""
    parsed = parse_url(url)

    url_len = len(url)
    domain_len = len(parsed.hostname)
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    domain_hyphen_count = parsed.hostname.count("-")

    if parsed.is_ip_literal or not parsed.subdomain:
        num_subdomains = 0
    else:
        num_subdomains = len([lbl for lbl in parsed.subdomain.split(".") if lbl])

    num_digits = sum(1 for ch in url if ch.isdigit())
    digit_ratio = round(num_digits / max(1, url_len), 4)
    path_length = len(parsed.path)
    query_length = len(parsed.query)
    num_query_params = len(parse_qsl(parsed.query, keep_blank_values=True)) if parsed.query else 0
    num_special_chars = sum(1 for ch in url if ch in SPECIAL_CHARS_SET)

    # Tokenize host/path/query to avoid substring false positives inside unrelated words
    searchable_text = f"{parsed.hostname}/{parsed.path}?{parsed.query}".lower()
    tokens = {tok for tok in TOKEN_SPLIT_RE.split(searchable_text) if tok}

    matched_keywords = sorted(
        kw for kw in SUSPICIOUS_KEYWORDS if (kw in tokens or ("-" in kw and kw in searchable_text))
    )

    # Brand impersonation: brand appears in subdomain/path/query while registered domain isn't the brand
    sub_and_path = f"{parsed.subdomain}/{parsed.path}?{parsed.query}".lower()
    sub_path_tokens = {tok for tok in TOKEN_SPLIT_RE.split(sub_and_path) if tok}
    reg_domain_base = parsed.registered_domain.split(".")[0].lower()
    matched_brands = sorted(
        b for b in BRAND_KEYWORDS if b in sub_path_tokens and b != reg_domain_base
    )

    # Suspicious TLD (handle multi-part suffixes by inspecting final label too)
    tld_lower = parsed.tld.lower()
    final_tld = tld_lower.split(".")[-1] if tld_lower else ""
    has_suspicious_tld = 1 if (tld_lower in SUSPICIOUS_TLDS or final_tld in SUSPICIOUS_TLDS) else 0

    # Unusual URL encoding (excessive %xx, double-encoding %25xx, or encoded '@' / '/')
    percent_matches = PERCENT_ENCODED_RE.findall(url)
    double_encoded_matches = DOUBLE_ENCODED_RE.findall(url)
    encoded_specials = sum(1 for seq in percent_matches if seq.upper() in {"%40", "%2F", "%5C", "%00"})
    unusual_encoding_count = len(double_encoded_matches) * 2 + encoded_specials + max(0, len(percent_matches) - 3)

    # Userinfo deception check (e.g. https://example.com@evil.example)
    userinfo_looks_like_domain = bool(
        parsed.username and "." in parsed.username and not parsed.username.startswith(".")
    )

    has_non_standard_port = 1 if (parsed.port is not None and parsed.port not in {80, 443}) else 0
    is_url_shortener = 1 if parsed.registered_domain in URL_SHORTENERS else 0

    numeric: Dict[str, float] = {
        "url_length": float(url_len),
        "domain_length": float(domain_len),
        "num_dots": float(num_dots),
        "num_hyphens": float(num_hyphens),
        "num_subdomains": float(num_subdomains),
        "num_digits": float(num_digits),
        "has_ip_address": float(1 if parsed.is_ip_literal else 0),
        "suspicious_keyword_count": float(len(matched_keywords)),
        "path_length": float(path_length),
        "num_special_chars": float(num_special_chars),
        "has_at_symbol": float(1 if parsed.has_at_symbol else 0),
        "is_https": float(1 if parsed.scheme == "https" else 0),
        "has_punycode_idn": float(1 if parsed.is_punycode_or_idn else 0),
        "has_suspicious_tld": float(has_suspicious_tld),
        "unusual_encoding_count": float(unusual_encoding_count),
        "query_length": float(query_length),
        "num_query_params": float(num_query_params),
        "url_entropy": float(shannon_entropy(url)),
        "domain_entropy": float(shannon_entropy(parsed.hostname)),
        "digit_ratio": float(digit_ratio),
        "has_userinfo_domain": float(1 if userinfo_looks_like_domain else 0),
        "domain_hyphen_count": float(domain_hyphen_count),
        "has_non_standard_port": float(has_non_standard_port),
        "is_url_shortener": float(is_url_shortener),
        "brand_in_subdomain_or_path": float(1 if matched_brands else 0),
    }

    return ExtractedFeatures(
        parsed=parsed,
        numeric=numeric,
        matched_keywords=matched_keywords,
        matched_brands=matched_brands,
        userinfo_looks_like_domain=userinfo_looks_like_domain,
        double_encoded_count=len(double_encoded_matches),
    )

