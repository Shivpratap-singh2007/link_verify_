from dataclasses import dataclass
from typing import List

from app.services.feature_extractor import ExtractedFeatures


@dataclass
class HeuristicSignal:
    code: str
    title: str
    severity: str  # info | low | medium | high | critical
    contribution: float
    description: str
    evidence: str


@dataclass
class HeuristicAnalysisResult:
    score: float  # 0 to 100
    signals: List[HeuristicSignal]
    feature_contributions: dict[str, float]


def analyze_heuristics(features: ExtractedFeatures) -> HeuristicAnalysisResult:
    """Evaluate multi-signal phishing heuristics without relying on any single indicator alone."""
    num = features.numeric
    parsed = features.parsed
    signals: List[HeuristicSignal] = []
    contributions: dict[str, float] = {name: 0.0 for name in num}

    strong_or_medium_count = 0

    # 1. IP address literal used instead of domain
    if num["has_ip_address"] == 1.0:
        pts = 28.0
        strong_or_medium_count += 1
        desc = "URL uses a direct IP address instead of a registered domain name, a common evasion technique."
        if parsed.is_private_ip:
            pts += 8.0
            desc += " Additionally, the address belongs to a private/non-public IP range."
        contributions["has_ip_address"] = pts
        signals.append(
            HeuristicSignal(
                code="IP_ADDRESS_HOST",
                title="IP address used instead of domain",
                severity="high",
                contribution=pts,
                description=desc,
                evidence=parsed.hostname,
            )
        )

    # 2. '@' symbol / userinfo host deception
    if num["has_at_symbol"] == 1.0:
        pts = 34.0
        strong_or_medium_count += 1
        desc = "URL contains an '@' character in the authority section, which browsers interpret as userinfo before the true destination host."
        if features.userinfo_looks_like_domain:
            pts += 16.0
            contributions["has_userinfo_domain"] = 16.0
            desc += f" The prefix '{parsed.username}' resembles a domain name, masking the real host '{parsed.hostname}'."
        contributions["has_at_symbol"] = 34.0
        signals.append(
            HeuristicSignal(
                code="AT_SYMBOL_DECEPTION",
                title="Authority deception using '@' symbol",
                severity="high",
                contribution=pts,
                description=desc,
                evidence=f"{parsed.username or ''}@{parsed.hostname}",
            )
        )

    # 3. Punycode / IDN homograph risk
    if num["has_punycode_idn"] == 1.0:
        pts = 24.0
        strong_or_medium_count += 1
        contributions["has_punycode_idn"] = pts
        signals.append(
            HeuristicSignal(
                code="PUNYCODE_IDN",
                title="Punycode / Internationalized Domain Name detected",
                severity="high",
                contribution=pts,
                description="Domain uses Punycode ('xn--') or non-ASCII characters, which can be abused in lookalike homograph attacks.",
                evidence=parsed.hostname,
            )
        )

    # 4. Brand impersonation in subdomain or path
    if num["brand_in_subdomain_or_path"] == 1.0:
        pts = 22.0
        strong_or_medium_count += 1
        contributions["brand_in_subdomain_or_path"] = pts
        signals.append(
            HeuristicSignal(
                code="BRAND_IMPERSONATION",
                title="Brand keyword outside registered domain",
                severity="high",
                contribution=pts,
                description="Well-known brand name appears in the subdomain or path while the registered domain does not belong to that brand.",
                evidence=", ".join(features.matched_brands),
            )
        )

    # 5. Suspicious keywords (never conclusive on their own on a clean domain)
    kw_count = int(num["suspicious_keyword_count"])
    if kw_count > 0:
        pts = min(22.0, float(kw_count) * 8.0)
        if kw_count >= 3:
            strong_or_medium_count += 1
        contributions["suspicious_keyword_count"] = pts
        signals.append(
            HeuristicSignal(
                code="SUSPICIOUS_KEYWORDS",
                title="Credential or account-action keywords detected",
                severity="medium" if kw_count >= 3 else "low",
                contribution=pts,
                description="URL contains terms commonly associated with login, verification, or account-recovery pages. Legitimate sites also use these terms, so context matters.",
                evidence=", ".join(features.matched_keywords),
            )
        )

    # 6. Excessive subdomains
    sub_count = int(num["num_subdomains"])
    if sub_count >= 3:
        pts = 15.0
        strong_or_medium_count += 1
        contributions["num_subdomains"] = pts
        signals.append(
            HeuristicSignal(
                code="EXCESSIVE_SUBDOMAINS",
                title="Excessive subdomain nesting",
                severity="medium",
                contribution=pts,
                description="URL uses three or more subdomain labels, a pattern often used to disguise the true registered domain.",
                evidence=parsed.subdomain,
            )
        )
    elif sub_count == 2:
        pts = 7.0
        contributions["num_subdomains"] = pts
        signals.append(
            HeuristicSignal(
                code="MULTIPLE_SUBDOMAINS",
                title="Multiple subdomains present",
                severity="low",
                contribution=pts,
                description="URL contains multiple subdomain levels.",
                evidence=parsed.subdomain,
            )
        )

    # 7. Unusual URL encoding
    enc_count = int(num["unusual_encoding_count"])
    if enc_count > 0:
        pts = 22.0 if features.double_encoded_count > 0 else 14.0
        strong_or_medium_count += 1
        contributions["unusual_encoding_count"] = pts
        signals.append(
            HeuristicSignal(
                code="UNUSUAL_ENCODING",
                title="Unusual URL percent-encoding",
                severity="high" if features.double_encoded_count > 0 else "medium",
                contribution=pts,
                description="URL uses double percent-encoding or encoded special delimiters that can obfuscate phishing destinations.",
                evidence=f"encoding_anomaly_score={enc_count}",
            )
        )

    # 8. Suspicious / high-abuse TLD
    if num["has_suspicious_tld"] == 1.0:
        pts = 12.0
        strong_or_medium_count += 1
        contributions["has_suspicious_tld"] = pts
        signals.append(
            HeuristicSignal(
                code="SUSPICIOUS_TLD",
                title="Uncommon or frequently abused TLD",
                severity="medium",
                contribution=pts,
                description="The top-level domain is frequently observed in disposable or phishing campaigns, though legitimate sites may also use it.",
                evidence=f".{parsed.tld}",
            )
        )

    # 9. Multiple hyphens in domain
    if num["domain_hyphen_count"] >= 2:
        pts = 10.0
        strong_or_medium_count += 1
        contributions["domain_hyphen_count"] = pts
        signals.append(
            HeuristicSignal(
                code="HYPHENATED_DOMAIN",
                title="Multiple hyphens in domain name",
                severity="medium",
                contribution=pts,
                description="Domains with multiple hyphens are commonly used for lookalike or spoofed brand domains.",
                evidence=parsed.hostname,
            )
        )

    # 10. URL shortener
    if num["is_url_shortener"] == 1.0:
        pts = 12.0
        strong_or_medium_count += 1
        contributions["is_url_shortener"] = pts
        signals.append(
            HeuristicSignal(
                code="URL_SHORTENER",
                title="URL shortening service hides final target",
                severity="medium",
                contribution=pts,
                description="Shortened URLs obscure the true destination domain until expanded.",
                evidence=parsed.registered_domain,
            )
        )

    # 11. Non-standard port
    if num["has_non_standard_port"] == 1.0:
        pts = 10.0
        strong_or_medium_count += 1
        contributions["has_non_standard_port"] = pts
        signals.append(
            HeuristicSignal(
                code="NON_STANDARD_PORT",
                title="Non-standard TCP port specified",
                severity="medium",
                contribution=pts,
                description="Legitimate consumer websites rarely serve pages on non-standard ports.",
                evidence=f":{parsed.port}",
            )
        )

    # 12. Missing HTTPS (weak indicator on its own — never conclusive alone)
    if num["is_https"] == 0.0:
        pts = 8.0
        contributions["is_https"] = pts
        signals.append(
            HeuristicSignal(
                code="NO_HTTPS",
                title="Unencrypted HTTP scheme",
                severity="low",
                contribution=pts,
                description="URL uses HTTP instead of HTTPS. Plain HTTP alone does not indicate phishing, but traffic is unencrypted.",
                evidence="http://",
            )
        )

    # 13. Unusual URL length (weak indicator on its own — never conclusive alone)
    url_len = int(num["url_length"])
    if url_len > 140:
        pts = 11.0
        contributions["url_length"] = pts
        signals.append(
            HeuristicSignal(
                code="VERY_LONG_URL",
                title="Unusually long URL",
                severity="low",
                contribution=pts,
                description="Very long URLs can be used to hide suspicious parameters or distract users, though tracking links can also be long.",
                evidence=f"{url_len} characters",
            )
        )
    elif url_len > 75:
        pts = 6.0
        contributions["url_length"] = pts
        signals.append(
            HeuristicSignal(
                code="LONG_URL",
                title="Extended URL length",
                severity="info",
                contribution=pts,
                description="URL exceeds 75 characters. Length alone is not malicious.",
                evidence=f"{url_len} characters",
            )
        )

    raw_total = sum(s.contribution for s in signals)

    # Compound risk amplification when multiple independent structural anomalies occur together
    if strong_or_medium_count >= 2 or (strong_or_medium_count >= 1 and num["is_https"] == 0.0 and kw_count >= 2):
        synergy = min(14.0, float(strong_or_medium_count) * 5.0 + (5.0 if num["is_https"] == 0.0 else 0.0))
        raw_total += synergy
        signals.append(
            HeuristicSignal(
                code="COMPOUND_ANOMALIES",
                title="Multiple corroborating risk indicators",
                severity="medium",
                contribution=synergy,
                description="Multiple independent structural anomalies appear together in this URL, elevating risk beyond any single signal.",
                evidence=f"corroborating_signals={strong_or_medium_count}",
            )
        )

    bounded_score = min(100.0, max(0.0, round(raw_total, 2)))
    return HeuristicAnalysisResult(
        score=bounded_score,
        signals=signals,
        feature_contributions=contributions,
    )

