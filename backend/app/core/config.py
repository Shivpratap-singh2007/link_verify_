from functools import lru_cache
from typing import List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "LINK VERIFY AI"
    app_version: str = "1.0.0"
    environment: str = "development"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # Database
    database_url: str = ""

    # Supabase Auth (optional in local dev; required for Supabase mode)
    supabase_url: str = ""
    supabase_anon_key: str = ""
    supabase_service_role_key: str = ""
    supabase_jwt_secret: str = ""

    # Local JWT Auth fallback (used when Supabase Auth is not configured)
    local_jwt_secret: str = "dev-only-insecure-change-me-before-production-32bytes"
    local_jwt_algorithm: str = "HS256"
    local_jwt_expire_minutes: int = 1440

    # Threat Intelligence (Backend-only)
    google_safe_browsing_api_key: str = ""
    virustotal_api_key: str = ""
    phishtank_api_key: str = ""
    urlhaus_auth_key: str = ""
    threat_intel_timeout_seconds: float = 4.0
    threat_intel_cache_ttl_seconds: int = 900

    # Rate Limiting
    rate_limit_scan_per_minute: int = 30
    rate_limit_auth_per_minute: int = 20

    # Configurable Risk Aggregation Weights
    risk_weight_ml: float = Field(default=0.50, ge=0.0, le=1.0)
    risk_weight_heuristic: float = Field(default=0.35, ge=0.0, le=1.0)
    risk_weight_threat_intel: float = Field(default=0.15, ge=0.0, le=1.0)

    # ML Model Artifact paths
    ml_model_path: str = ""
    ml_metadata_path: str = ""

    @field_validator("database_url", mode="before")
    @classmethod
    def default_database_url(cls, v: str | None) -> str:
        if not v or not str(v).strip():
            return "sqlite:///./link_verify_local.db"
        raw = str(v).strip()
        # Normalize postgres:// or postgresql:// to SQLAlchemy psycopg3 driver
        if raw.startswith("postgres://"):
            return "postgresql+psycopg://" + raw[len("postgres://"):]
        if raw.startswith("postgresql://"):
            return "postgresql+psycopg://" + raw[len("postgresql://"):]
        return raw

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url.strip() and (self.supabase_jwt_secret.strip() or self.supabase_anon_key.strip()))

    @property
    def auth_mode(self) -> str:
        return "supabase" if self.supabase_configured else "local_jwt"


@lru_cache
def get_settings() -> Settings:
    return Settings()

