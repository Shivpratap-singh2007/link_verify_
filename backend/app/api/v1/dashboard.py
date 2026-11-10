from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database.session import get_db
from app.models.db_models import Scan
from app.schemas.dashboard import (
    DailyActivityItem,
    DashboardStatsResponse,
    RiskDistributionItem,
)
from app.schemas.scan import ScanSummarySchema
from app.security.auth import AuthenticatedUser

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DashboardStatsResponse:
    user_scans = db.scalars(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
    ).all()

    total_scans = len(user_scans)
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    score_sum = 0

    for s in user_scans:
        counts[s.risk_level] = counts.get(s.risk_level, 0) + 1
        score_sum += s.risk_score

    avg_score = round(score_sum / total_scans, 1) if total_scans > 0 else 0.0

    # Last 14 days activity timeline from real persisted scans
    today = datetime.now(timezone.utc).date()
    day_buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "high_or_critical": 0})
    for offset in range(13, -1, -1):
        day_str = (today - timedelta(days=offset)).isoformat()
        _ = day_buckets[day_str]

    for s in user_scans:
        scan_date = s.created_at.date().isoformat()
        if scan_date in day_buckets:
            day_buckets[scan_date]["total"] += 1
            if s.risk_level in {"HIGH", "CRITICAL"}:
                day_buckets[scan_date]["high_or_critical"] += 1

    activity = [
        DailyActivityItem(
            date=day_str,
            total=vals["total"],
            high_or_critical=vals["high_or_critical"],
        )
        for day_str, vals in day_buckets.items()
    ]

    risk_distribution = [
        RiskDistributionItem(risk_level=level, count=counts[level])
        for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    ]

    recent = [
        ScanSummarySchema(
            id=row.id,
            original_url=row.original_url,
            normalized_domain=row.normalized_domain,
            risk_score=row.risk_score,
            risk_level=row.risk_level,  # type: ignore[arg-type]
            model_confidence=row.model_confidence,
            verdict=row.verdict,
            scan_status=row.scan_status,
            created_at=row.created_at,
        )
        for row in user_scans[:5]
    ]

    return DashboardStatsResponse(
        total_scans=total_scans,
        low_risk_count=counts["LOW"],
        medium_risk_count=counts["MEDIUM"],
        high_risk_count=counts["HIGH"],
        critical_risk_count=counts["CRITICAL"],
        average_risk_score=avg_score,
        risk_distribution=risk_distribution,
        scan_activity=activity,
        recent_scans=recent,
    )

