from functools import lru_cache
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.database.session import get_db
from app.ml.predictor import MLModelPredictor
from app.security.auth import AuthenticatedUser, decode_bearer_token
from app.security.rate_limit import get_client_identifier, rate_limiter
from app.services.scan_service import ScanService

bearer_scheme = HTTPBearer(auto_error=False)


@lru_cache
def get_ml_predictor() -> MLModelPredictor:
    return MLModelPredictor(get_settings())


def get_scan_service(
    predictor: MLModelPredictor = Depends(get_ml_predictor),
    settings: Settings = Depends(get_settings),
) -> ScanService:
    return ScanService(predictor=predictor, settings=settings)


def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> Optional[AuthenticatedUser]:
    if credentials is None or not credentials.credentials:
        return None
    return decode_bearer_token(credentials.credentials, settings=settings)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> AuthenticatedUser:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decode_bearer_token(credentials.credentials, settings=settings)


def enforce_scan_rate_limit(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> None:
    client_id = get_client_identifier(request)
    rate_limiter.check(f"scan:{client_id}", max_requests=settings.rate_limit_scan_per_minute, window_seconds=60)


def enforce_auth_rate_limit(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> None:
    client_id = get_client_identifier(request)
    rate_limiter.check(f"auth:{client_id}", max_requests=settings.rate_limit_auth_per_minute, window_seconds=60)

