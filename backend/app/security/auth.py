import base64
import hashlib
import hmac
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import HTTPException, status

from app.core.config import Settings, get_settings


@dataclass
class AuthenticatedUser:
    id: uuid.UUID
    email: str
    display_name: str
    auth_provider: str


def hash_password(password: str) -> str:
    """Hash password with PBKDF2-HMAC-SHA256 and per-user random salt."""
    salt = os.urandom(16)
    iterations = 260_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (
        f"pbkdf2_sha256${iterations}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(dk).decode('ascii')}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored PBKDF2 hash in constant time."""
    try:
        algo, iter_str, salt_b64, hash_b64 = stored_hash.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(hash_b64.encode("ascii"))
        computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(computed, expected)
    except (ValueError, TypeError):
        return False


def create_local_access_token(
    user_id: uuid.UUID,
    email: str,
    display_name: str,
    settings: Optional[Settings] = None,
) -> str:
    cfg = settings or get_settings()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=cfg.local_jwt_expire_minutes)
    payload = {
        "sub": str(user_id),
        "email": email,
        "display_name": display_name,
        "iss": "link-verify-ai-local",
        "aud": "authenticated",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, cfg.local_jwt_secret, algorithm=cfg.local_jwt_algorithm)


def decode_bearer_token(token: str, settings: Optional[Settings] = None) -> AuthenticatedUser:
    """Decode and verify a JWT token from Supabase Auth or local JWT mode."""
    cfg = settings or get_settings()
    if not token or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Try Supabase JWT verification first when configured
    if cfg.supabase_configured:
        try:
            header = jwt.get_unverified_header(token)
            alg = header.get("alg", "HS256")
            if alg == "HS256" and cfg.supabase_jwt_secret:
                payload = jwt.decode(
                    token,
                    cfg.supabase_jwt_secret,
                    algorithms=["HS256"],
                    audience="authenticated",
                )
            elif cfg.supabase_url:
                jwks_url = f"{cfg.supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json"
                jwk_client = jwt.PyJWKClient(jwks_url)
                signing_key = jwk_client.get_signing_key_from_jwt(token)
                payload = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256", "ES256"],
                    audience="authenticated",
                )
            else:
                raise jwt.InvalidTokenError("Supabase verification secret/URL missing.")

            user_id = uuid.UUID(str(payload["sub"]))
            email = str(payload.get("email") or "")
            meta = payload.get("user_metadata") or {}
            display_name = str(meta.get("display_name") or (email.split("@")[0] if email else "User"))
            return AuthenticatedUser(
                id=user_id,
                email=email,
                display_name=display_name,
                auth_provider="supabase",
            )
        except (jwt.PyJWTError, ValueError, KeyError) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired Supabase authentication token.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

    # Local JWT verification mode
    try:
        payload = jwt.decode(
            token,
            cfg.local_jwt_secret,
            algorithms=[cfg.local_jwt_algorithm],
            audience="authenticated",
        )
        user_id = uuid.UUID(str(payload["sub"]))
        email = str(payload.get("email") or "")
        display_name = str(payload.get("display_name") or (email.split("@")[0] if email else "User"))
        return AuthenticatedUser(
            id=user_id,
            email=email,
            display_name=display_name,
            auth_provider="local_jwt",
        )
    except (jwt.PyJWTError, ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

