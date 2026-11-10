from typing import Any, Dict, Optional
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    database_engine: str
    auth_mode: str
    ml_model_loaded: bool


class ModelStatusResponse(BaseModel):
    model_loaded: bool
    status: str
    message: str
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    trained_at: Optional[str] = None
    dataset: Optional[Dict[str, Any]] = None
    feature_names: list[str]
    metrics: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    detail: str
    code: Optional[str] = None

