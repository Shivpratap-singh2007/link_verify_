from app.ml.predictor import MLPredictionResult
from app.services.feature_extractor import FEATURE_NAMES, extract_url_features
from app.services.heuristic_analyzer import analyze_heuristics
from app.services.risk_aggregator import aggregate_risk
from app.services.threat_intel.base import ThreatIntelResult


def test_feature_extractor_extracts_all_15_plus_features():
    url = "https://secure.login-portal.example.xyz/account/verify?session=12345&next=%2Fhome"
    feat = extract_url_features(url)

    for name in FEATURE_NAMES:
        assert name in feat.numeric

    assert feat.numeric["url_length"] == float(len(url))
    assert feat.numeric["is_https"] == 1.0
    assert feat.numeric["has_ip_address"] == 0.0
    assert feat.numeric["has_at_symbol"] == 0.0
    assert feat.numeric["has_suspicious_tld"] == 1.0
    assert feat.numeric["num_subdomains"] == 2.0
    assert feat.numeric["suspicious_keyword_count"] >= 3.0
    assert feat.numeric["num_query_params"] == 2.0


def test_at_symbol_userinfo_deception_extracts_true_host():
    url = "https://example.com@evil.example"
    feat = extract_url_features(url)

    assert feat.parsed.hostname == "evil.example"
    assert feat.parsed.username == "example.com"
    assert feat.numeric["has_at_symbol"] == 1.0
    assert feat.numeric["has_userinfo_domain"] == 1.0

    heuristics = analyze_heuristics(feat)
    codes = {s.code for s in heuristics.signals}
    assert "AT_SYMBOL_DECEPTION" in codes
    assert heuristics.score >= 50.0


def test_single_weak_indicator_never_marks_url_high_or_critical():
    # Plain HTTP alone on a benign domain
    http_feat = extract_url_features("http://example.com")
    http_heur = analyze_heuristics(http_feat)
    assert http_heur.score < 25.0

    # Long URL alone on clean HTTPS domain
    long_url = "https://example.com/articles/engineering/" + ("a" * 120)
    long_feat = extract_url_features(long_url)
    long_heur = analyze_heuristics(long_feat)
    assert long_heur.score < 25.0

    # Clean HTTPS URL with login/verify path keywords only
    login_feat = extract_url_features("https://example.com/login/verify")
    login_heur = analyze_heuristics(login_feat)
    assert login_heur.score < 25.0


def test_compound_phishing_indicators_elevate_score():
    # IP literal + HTTP + private range + /login/verify keywords
    feat = extract_url_features("http://192.168.1.1/login/verify")
    heur = analyze_heuristics(feat)
    codes = {s.code for s in heur.signals}
    assert "IP_ADDRESS_HOST" in codes
    assert "SUSPICIOUS_KEYWORDS" in codes
    assert "NO_HTTPS" in codes
    assert heur.score >= 50.0


def test_punycode_and_double_encoding_detection():
    feat = extract_url_features("https://xn--pypal-4ve.com/auth%252Flogin%40confirm")
    assert feat.numeric["has_punycode_idn"] == 1.0
    assert feat.numeric["unusual_encoding_count"] > 0.0
    heur = analyze_heuristics(feat)
    codes = {s.code for s in heur.signals}
    assert "PUNYCODE_IDN" in codes
    assert "UNUSUAL_ENCODING" in codes


def test_risk_aggregator_keeps_confidence_separate_and_never_guarantees_safety():
    feat = extract_url_features("https://example.com")
    heur = analyze_heuristics(feat)
    ml = MLPredictionResult(
        model_loaded=True,
        model_name="xgboost",
        model_version="1.0.0",
        phishing_probability=0.04,
        model_confidence=0.96,
        predicted_label="benign",
        status_message="ok",
    )
    ti = [
        ThreatIntelResult(
            provider="google_safe_browsing",
            detection_status="not_configured",
            message="Threat intelligence service not configured.",
        )
    ]

    agg = aggregate_risk(heur, ml, ti)
    assert agg.risk_level == "LOW"
    assert agg.risk_score <= 24
    assert agg.model_confidence == 0.96
    assert "No known threat detected" in agg.verdict
    assert "does not guarantee" in agg.safety_disclaimer


def test_risk_aggregator_prioritizes_confirmed_threat_intel_hit():
    feat = extract_url_features("https://clean-looking-domain.example/page")
    heur = analyze_heuristics(feat)
    ml = MLPredictionResult(
        model_loaded=True,
        model_name="xgboost",
        model_version="1.0.0",
        phishing_probability=0.10,
        model_confidence=0.90,
        predicted_label="benign",
        status_message="ok",
    )
    ti = [
        ThreatIntelResult(
            provider="google_safe_browsing",
            detection_status="malicious",
            message="Matched SOCIAL_ENGINEERING",
        )
    ]

    agg = aggregate_risk(heur, ml, ti)
    assert agg.risk_score >= 75
    assert agg.risk_level == "CRITICAL"

