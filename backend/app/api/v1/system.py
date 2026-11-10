from fastapi import APIRouter, Depends

from app.api.deps import get_ml_predictor
from app.core.config import Settings, get_settings
from app.ml.predictor import MLModelPredictor
from app.schemas.common import HealthResponse, ModelStatusResponse

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
def health_check(
    settings: Settings = Depends(get_settings),
    predictor: MLModelPredictor = Depends(get_ml_predictor),
) -> HealthResponse:
    db_engine = "postgresql" if "postgresql" in settings.database_url else "sqlite"
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        database_engine=db_engine,
        auth_mode=settings.auth_mode,
        ml_model_loaded=predictor.is_ready,
    )


@router.get("/model/status", response_model=ModelStatusResponse)
def model_status(
    predictor: MLModelPredictor = Depends(get_ml_predictor),
) -> ModelStatusResponse:
    return ModelStatusResponse.model_validate(predictor.get_status())

