from typing import List
from pydantic import BaseModel

from app.schemas.scan import ScanSummarySchema


class RiskDistributionItem(BaseModel):
    risk_level: str
    count: int


class DailyActivityItem(BaseModel):
    date: str
    total: int
    high_or_critical: int


class DashboardStatsResponse(BaseModel):
    total_scans: int
    low_risk_count: int
    medium_risk_count: int
    high_risk_count: int
    critical_risk_count: int
    average_risk_score: float
    risk_distribution: List[RiskDistributionItem]
    scan_activity: List[DailyActivityItem]
    recent_scans: List[ScanSummarySchema]

