import math
import uuid
from datetime import datetime, time, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import (
    enforce_scan_rate_limit,
    get_current_user,
    get_optional_user,
    get_scan_service,
)
from app.database.session import get_db
from app.models.db_models import Scan, ScanReport
from app.schemas.scan import (
    DeleteScanResponse,
    PaginatedScansResponse,
    RiskLevel,
    ScanReportResponse,
    ScanRequest,
    ScanSummarySchema,
)
from app.security.auth import AuthenticatedUser
from app.security.ssrf import SSRFBlockedError, URLValidationError
from app.services.scan_service import ScanService

router = APIRouter(tags=["URL Scanning"])


@router.post(
    "/scan",
    response_model=ScanReportResponse,
    dependencies=[Depends(enforce_scan_rate_limit)],
)
async def submit_url_scan(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    current_user: Optional[AuthenticatedUser] = Depends(get_optional_user),
    scan_service: ScanService = Depends(get_scan_service),
) -> ScanReportResponse:
    try:
        return await scan_service.analyze_and_optionally_persist(
            raw_url=payload.url,
            db=db,
            current_user=current_user,
        )
    except SSRFBlockedError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.message,
        ) from exc
    except URLValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.message,
        ) from exc


@router.get("/scans", response_model=PaginatedScansResponse)
def list_user_scans(
    search: Optional[str] = Query(default=None, max_length=200),
    risk_level: Optional[RiskLevel] = Query(default=None),
    domain: Optional[str] = Query(default=None, max_length=255),
    date_from: Optional[str] = Query(default=None, description="ISO date YYYY-MM-DD"),
    date_to: Optional[str] = Query(default=None, description="ISO date YYYY-MM-DD"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PaginatedScansResponse:
    filters = [Scan.user_id == current_user.id]

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        filters.append(
            or_(
                func.lower(Scan.original_url).like(term),
                func.lower(Scan.normalized_domain).like(term),
                func.lower(Scan.verdict).like(term),
            )
        )

    if risk_level:
        filters.append(Scan.risk_level == risk_level)

    if domain and domain.strip():
        filters.append(func.lower(Scan.normalized_domain).like(f"%{domain.strip().lower()}%"))

    if date_from:
        try:
            d_from = datetime.strptime(date_from, "%Y-%m-%d").date()
            filters.append(Scan.created_at >= datetime.combine(d_from, time.min, tzinfo=timezone.utc))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid date_from format; expected YYYY-MM-DD.") from exc

    if date_to:
        try:
            d_to = datetime.strptime(date_to, "%Y-%m-%d").date()
            filters.append(Scan.created_at <= datetime.combine(d_to, time.max, tzinfo=timezone.utc))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid date_to format; expected YYYY-MM-DD.") from exc

    total = db.scalar(select(func.count()).select_from(Scan).where(*filters)) or 0
    total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1

    rows = db.scalars(
        select(Scan)
        .where(*filters)
        .order_by(Scan.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    items = [
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
        for row in rows
    ]

    return PaginatedScansResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/scans/{scan_id}", response_model=ScanReportResponse)
def get_scan_report(
    scan_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanReportResponse:
    scan = db.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")

    report_row = db.scalar(select(ScanReport).where(ScanReport.scan_id == scan.id))
    if report_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan report payload not found.")

    return ScanReportResponse.model_validate(report_row.report_data)


@router.delete("/scans/{scan_id}", response_model=DeleteScanResponse)
def delete_scan_record(
    scan_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DeleteScanResponse:
    scan = db.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found.")

    db.delete(scan)
    db.commit()
    return DeleteScanResponse(deleted=True, id=scan_id)

