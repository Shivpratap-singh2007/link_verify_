import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import enforce_auth_rate_limit, get_current_user
from app.core.config import Settings, get_settings
from app.database.session import get_db
from app.models.db_models import Profile
from app.schemas.auth import (
    AuthTokenResponse,
    LoginRequest,
    PasswordResetRequest,
    ProfileUpdateRequest,
    RegisterRequest,
    UserProfileResponse,
)
from app.security.auth import (
    AuthenticatedUser,
    create_local_access_token,
    hash_password,
    verify_password,
)
from app.services.scan_service import ScanService

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _to_profile_response(profile: Profile, auth_provider: str) -> UserProfileResponse:
    return UserProfileResponse(
        id=profile.id,
        email=profile.email,
        display_name=profile.display_name,
        auth_provider=auth_provider,
        created_at=profile.created_at,
    )


@router.post(
    "/register",
    response_model=AuthTokenResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_auth_rate_limit)],
)
def register_local_user(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AuthTokenResponse:
    if settings.supabase_configured:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Supabase Authentication is active. Please register through Supabase Auth client.",
        )

    normalized_email = payload.email.strip().lower()
    existing = db.scalar(select(Profile).where(Profile.email == normalized_email))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    display_name = payload.display_name.strip() or normalized_email.split("@")[0]
    profile = Profile(
        id=uuid.uuid4(),
        email=normalized_email,
        display_name=display_name,
        password_hash=hash_password(payload.password),
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)

    token = create_local_access_token(profile.id, profile.email, profile.display_name, settings=settings)
    return AuthTokenResponse(
        access_token=token,
        auth_mode="local_jwt",
        user=_to_profile_response(profile, "local_jwt"),
    )


@router.post(
    "/login",
    response_model=AuthTokenResponse,
    dependencies=[Depends(enforce_auth_rate_limit)],
)
def login_local_user(
    payload: LoginRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AuthTokenResponse:
    if settings.supabase_configured:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Supabase Authentication is active. Please sign in through Supabase Auth client.",
        )

    normalized_email = payload.email.strip().lower()
    profile = db.scalar(select(Profile).where(Profile.email == normalized_email))
    if profile is None or not profile.password_hash or not verify_password(payload.password, profile.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    token = create_local_access_token(profile.id, profile.email, profile.display_name, settings=settings)
    return AuthTokenResponse(
        access_token=token,
        auth_mode="local_jwt",
        user=_to_profile_response(profile, "local_jwt"),
    )


@router.post(
    "/reset-password",
    dependencies=[Depends(enforce_auth_rate_limit)],
)
def reset_password_local(
    payload: PasswordResetRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    if settings.supabase_configured:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use Supabase Auth resetPasswordForEmail when Supabase Authentication is active.",
        )

    normalized_email = payload.email.strip().lower()
    profile = db.scalar(select(Profile).where(Profile.email == normalized_email))

    # Avoid account enumeration when no new_password is supplied
    if payload.new_password and profile is not None:
        profile.password_hash = hash_password(payload.new_password)
        db.add(profile)
        db.commit()
        return {"message": "Password updated successfully."}

    return {"message": "If an account exists for that email, password reset instructions have been processed."}


@router.get("/me", response_model=UserProfileResponse)
def get_my_profile(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserProfileResponse:
    profile = ScanService.ensure_user_profile(db, current_user)
    return _to_profile_response(profile, current_user.auth_provider)


@router.patch("/me", response_model=UserProfileResponse)
def update_my_profile(
    payload: ProfileUpdateRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserProfileResponse:
    profile = ScanService.ensure_user_profile(db, current_user)
    profile.display_name = payload.display_name.strip()
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return _to_profile_response(profile, current_user.auth_provider)

