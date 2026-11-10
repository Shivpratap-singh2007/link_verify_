from dataclasses import dataclass
from typing import List, Optional

from app.core.config import Settings, get_settings
from app.ml.predictor import MLPredictionResult
from app.services.heuristic_analyzer import HeuristicAnalysisResult
from app.services.threat_intel.base import ThreatIntelResult


@dataclass
class EvidenceContribution:
    source: str
    raw_score: Optional[float]
    effective_weight: float
    status: str
    summary: str


@dataclass
class AggregatedRiskResult:
    risk_score: int                  # 0-100
    risk_level: str                  # LOW | MEDIUM | HIGH | CRITICAL
    verdict: str                     # Non-absolute wording
    model_confidence: Optional[float]
    threat_intel_status: str         # clean | malicious | suspicious | not_configured | partial
    evidence_breakdown: List[EvidenceContribution]
    recommendations: List[str]
    safety_disclaimer: str


def classify_risk_level(score: int) -> str:
    if score <= 24:
        return "LOW"
    if score <= 49:
        return "MEDIUM"
    if score <= 74:
        return "HIGH"
    return "CRITICAL"


def aggregate_risk(
    heuristics: HeuristicAnalysisResult,
    ml_result: MLPredictionResult,
    threat_intel_results: List[ThreatIntelResult],
    settings: Optional[Settings] = None,
) -> AggregatedRiskResult:
    """Combine ML prediction, heuristic signals, and threat intelligence transparently.

    - Keeps ML confidence separate from the overall 0-100 risk score.
    - Never blindly averages away confirmed malicious threat intelligence matches.
    - Never penalizes or artificially suppresses risk when optional APIs or models are absent.
    - Never claims guaranteed safety for low-risk URLs.
    """
    cfg = settings or get_settings()

    # 1. Summarize Threat Intelligence evidence
    malicious_hits = [r for r in threat_intel_results if r.detection_status == "malicious"]
    suspicious_hits = [r for r in threat_intel_results if r.detection_status == "suspicious"]
    clean_hits = [r for r in threat_intel_results if r.detection_status == "clean"]
    configured_responders = malicious_hits + suspicious_hits + clean_hits

    if malicious_hits:
        ti_status = "malicious"
        ti_score: Optional[float] = 100.0
        ti_summary = f"Confirmed malicious indicator from {', '.join(r.provider for r in malicious_hits)}."
    elif suspicious_hits:
        ti_status = "suspicious"
        ti_score = 70.0
        ti_summary = f"Suspicious findings from {', '.join(r.provider for r in suspicious_hits)}."
    elif clean_hits:
        ti_status = "clean" if len(clean_hits) == len(threat_intel_results) else "partial"
        ti_score = 0.0
        ti_summary = f"{len(clean_hits)} configured provider(s) reported no known threat."
    else:
        not_conf = sum(1 for r in threat_intel_results if r.detection_status == "not_configured")
        ti_status = "not_configured" if not_conf == len(threat_intel_results) else "unavailable"
        ti_score = None
        ti_summary = "Threat intelligence service not configured or unavailable for this target."

    # 2. Compute active weights over available evidence sources
    active_sources: list[tuple[str, float, float, str, str]] = []
    # Heuristics are always available
    active_sources.append(
        (
            "Heuristic URL Engine",
            heuristics.score,
            cfg.risk_weight_heuristic,
            "active",
            f"Evaluated {len(heuristics.signals)} signal(s) with static structural scoring.",
        )
    )

    ml_score_100: Optional[float] = None
    if ml_result.model_loaded and ml_result.phishing_probability is not None:
        ml_score_100 = round(ml_result.phishing_probability * 100.0, 2)
        active_sources.append(
            (
                f"ML Classifier ({ml_result.model_name or 'model'})",
                ml_score_100,
                cfg.risk_weight_ml,
                "active",
                f"Predicted phishing probability {ml_score_100:.1f}% (confidence {ml_result.model_confidence:.2%}).",
            )
        )

    if ti_score is not None:
        active_sources.append(
            (
                "Threat Intelligence Feeds",
                ti_score,
                cfg.risk_weight_threat_intel,
                ti_status,
                ti_summary,
            )
        )

    total_weight = sum(w for _, _, w, _, _ in active_sources) or 1.0
    weighted_sum = sum(score * (w / total_weight) for _, score, w, _, _ in active_sources)

    evidence_breakdown: List[EvidenceContribution] = [
        EvidenceContribution(
            source=src,
            raw_score=round(sc, 2),
            effective_weight=round(w / total_weight, 4),
            status=st,
            summary=sm,
        )
        for src, sc, w, st, sm in active_sources
    ]

    if not ml_result.model_loaded:
        evidence_breakdown.append(
            EvidenceContribution(
                source="ML Classifier",
                raw_score=None,
                effective_weight=0.0,
                status="not_trained",
                summary=ml_result.status_message,
            )
        )

    if ti_score is None:
        evidence_breakdown.append(
            EvidenceContribution(
                source="Threat Intelligence Feeds",
                raw_score=None,
                effective_weight=0.0,
                status=ti_status,
                summary=ti_summary,
            )
        )

    # 3. Priority overrides so strong confirmed threats are never diluted by averaging
    final_float = weighted_sum
    if len(malicious_hits) >= 2:
        final_float = max(final_float, 92.0)
    elif len(malicious_hits) == 1:
        final_float = max(final_float, 80.0)
    elif suspicious_hits:
        final_float = max(final_float, 55.0)

    # Do not let benign ML predictions mask strong high-severity structural deception (e.g. userinfo '@' or IP+keywords)
    if heuristics.score >= 50.0:
        final_float = max(final_float, heuristics.score)

    risk_score = int(max(0, min(100, round(final_float))))
    risk_level = classify_risk_level(risk_score)

    if risk_level == "LOW":
        verdict = "No known threat detected."
    elif risk_level == "MEDIUM":
        verdict = "Suspicious characteristics observed; verify destination before interacting."
    elif risk_level == "HIGH":
        verdict = "High phishing risk indicators detected; avoid entering credentials or sensitive data."
    else:
        verdict = "Critical phishing or malicious risk detected; do not open or trust this link."

    recommendations = _build_recommendations(risk_level, heuristics, ti_status)
    safety_disclaimer = (
        "A low risk score does not guarantee that a website is safe. "
        "Newly created phishing pages, compromised legitimate domains, and post-redirect content "
        "may not be reflected in static URL analysis."
    )

    return AggregatedRiskResult(
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        model_confidence=ml_result.model_confidence,
        threat_intel_status=ti_status,
        evidence_breakdown=evidence_breakdown,
        recommendations=recommendations,
        safety_disclaimer=safety_disclaimer,
    )


def _build_recommendations(
    risk_level: str,
    heuristics: HeuristicAnalysisResult,
    ti_status: str,
) -> List[str]:
    recs: List[str] = []
    codes = {s.code for s in heuristics.signals}

    if risk_level in {"HIGH", "CRITICAL"}:
        recs.append("Do not enter passwords, payment details, or multi-factor authentication codes on this page.")
        recs.append("Navigate directly to the official service by typing its known domain manually rather than following this link.")
    elif risk_level == "MEDIUM":
        recs.append("Verify the sender and inspect the registered domain carefully before opening the link.")
    else:
        recs.append("Confirm the domain spelling and sender identity before signing in or sharing sensitive data.")

    if "AT_SYMBOL_DECEPTION" in codes:
        recs.append("Beware of '@' authority spoofing: browsers ignore text before '@' and connect to the domain after '@'.")
    if "IP_ADDRESS_HOST" in codes:
        recs.append("Legitimate public services rarely ask users to authenticate directly via raw IP URLs.")
    if "PUNYCODE_IDN" in codes:
        recs.append("Check for homograph character substitutions in the domain name.")
    if "NO_HTTPS" in codes:
        recs.append("Avoid transmitting sensitive information over unencrypted HTTP connections.")
    if ti_status in {"not_configured", "unavailable"}:
        recs.append("External threat intelligence feeds were not configured or skipped; rely on additional verification if uncertain.")

    return recs
