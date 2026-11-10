from datetime import datetime, timezone
import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.ml.predictor import MLModelPredictor
from app.models.db_models import Profile, Scan, ScanFeature, ScanReport, ThreatIntelligence
from app.schemas.scan import (
    DetectionIndicatorSchema,
    EvidenceBreakdownSchema,
    ExtractedFeatureSchema,
    MLDetailsSchema,
    ScanReportResponse,
    ThreatIntelEntrySchema,
)
from app.security.auth import AuthenticatedUser
from app.security.sanitization import redact_secrets, sanitize_text
from app.security.ssrf import validate_submitted_url
from app.services.feature_extractor import FEATURE_NAMES, extract_url_features
from app.services.heuristic_analyzer import analyze_heuristics
from app.services.risk_aggregator import aggregate_risk
from app.services.threat_intel.orchestrator import ThreatIntelOrchestrator


class ScanService:
    """Coordinates static URL validation, feature extraction, heuristics, ML, threat intel, and persistence."""

    def __init__(
        self,
        predictor: MLModelPredictor,
        threat_orchestrator: Optional[ThreatIntelOrchestrator] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.predictor = predictor
        self.threat_orchestrator = threat_orchestrator or ThreatIntelOrchestrator(self.settings)

    @staticmethod
    def ensure_user_profile(db: Session, auth_user: AuthenticatedUser) -> Profile:
        profile = db.get(Profile, auth_user.id)
        if profile is None:
            profile = Profile(
                id=auth_user.id,
                email=auth_user.email or f"{auth_user.id}@local.invalid",
                display_name=auth_user.display_name or "Analyst",
            )
            db.add(profile)
            db.commit()
            db.refresh(profile)
        return profile

    async def analyze_and_optionally_persist(
        self,
        raw_url: str,
        db: Session,
        current_user: Optional[AuthenticatedUser] = None,
    ) -> ScanReportResponse:
        validated_url = validate_submitted_url(raw_url)
        extracted = extract_url_features(validated_url)
        heuristics = analyze_heuristics(extracted)
        ml_result = self.predictor.predict(extracted)
        ti_results = await self.threat_orchestrator.evaluate(validated_url, extracted.parsed)
        aggregated = aggregate_risk(
            heuristics=heuristics,
            ml_result=ml_result,
            threat_intel_results=ti_results,
            settings=self.settings,
        )

        scanned_at = datetime.now(timezone.utc)

        indicators = [
            DetectionIndicatorSchema(
                code=sig.code,
                title=sig.title,
                severity=sig.severity,
                contribution=round(sig.contribution, 2),
                description=sig.description,
                evidence=sanitize_text(sig.evidence, max_length=256),
            )
            for sig in heuristics.signals
        ]

        feature_entries = [
            ExtractedFeatureSchema(
                feature_name=fname,
                feature_value=str(extracted.numeric[fname]),
                risk_contribution=round(float(heuristics.feature_contributions.get(fname, 0.0)), 2),
            )
            for fname in FEATURE_NAMES
        ]

        ti_entries = [
            ThreatIntelEntrySchema(
                provider=item.provider,
                detection_status=item.detection_status,
                message=sanitize_text(item.message, max_length=512),
                details=redact_secrets(item.details),
                cached=item.cached,
            )
            for item in ti_results
        ]

        evidence_entries = [
            EvidenceBreakdownSchema(
                source=ev.source,
                raw_score=ev.raw_score,
                effective_weight=ev.effective_weight,
                status=ev.status,
                summary=ev.summary,
            )
            for ev in aggregated.evidence_breakdown
        ]

        ml_details = MLDetailsSchema(
            model_loaded=ml_result.model_loaded,
            model_name=ml_result.model_name,
            model_version=ml_result.model_version,
            phishing_probability=ml_result.phishing_probability,
            model_confidence=ml_result.model_confidence,
            predicted_label=ml_result.predicted_label,
            status_message=ml_result.status_message,
        )

        report = ScanReportResponse(
            id=None,
            persisted=False,
            submitted_url=sanitize_text(validated_url, max_length=2048),
            normalized_domain=sanitize_text(extracted.parsed.hostname, max_length=255),
            registered_domain=sanitize_text(extracted.parsed.registered_domain, max_length=255),
            scheme=extracted.parsed.scheme,
            is_https=extracted.parsed.scheme == "https",
            risk_score=aggregated.risk_score,
            risk_level=aggregated.risk_level,  # type: ignore[arg-type]
            verdict=aggregated.verdict,
            model_confidence=aggregated.model_confidence,
            threat_intel_status=aggregated.threat_intel_status,
            scan_status="completed",
            ml_details=ml_details,
            detection_indicators=indicators,
            extracted_features=feature_entries,
            threat_intelligence=ti_entries,
            evidence_breakdown=evidence_entries,
            recommendations=aggregated.recommendations,
            safety_disclaimer=aggregated.safety_disclaimer,
            scanned_at=scanned_at,
        )

        if current_user is not None:
            self.ensure_user_profile(db, current_user)
            scan_id = uuid.uuid4()
            scan_row = Scan(
                id=scan_id,
                user_id=current_user.id,
                original_url=report.submitted_url,
                normalized_domain=report.normalized_domain,
                risk_score=report.risk_score,
                risk_level=report.risk_level,
                model_confidence=report.model_confidence,
                verdict=report.verdict,
                scan_status="completed",
                created_at=scanned_at,
            )
            db.add(scan_row)

            for feat in feature_entries:
                db.add(
                    ScanFeature(
                        scan_id=scan_id,
                        feature_name=feat.feature_name,
                        feature_value=feat.feature_value,
                        risk_contribution=feat.risk_contribution,
                    )
                )

            for ti in ti_entries:
                db.add(
                    ThreatIntelligence(
                        scan_id=scan_id,
                        provider=ti.provider,
                        detection_status=ti.detection_status,
                        details=redact_secrets({"message": ti.message, **ti.details}),
                        checked_at=scanned_at,
                    )
                )

            report.id = scan_id
            report.persisted = True
            serialized_report = redact_secrets(report.model_dump(mode="json"))
            db.add(
                ScanReport(
                    scan_id=scan_id,
                    report_data=serialized_report,
                    created_at=scanned_at,
                )
            )
            db.commit()

        return report

