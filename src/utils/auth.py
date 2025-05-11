from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt

from src.core.config import TOKEN_TYPE_FIELD
from src.core.settings import settings


def create_jwt(
        token_type: str,
        payload: dict[str, Any],
        expire_delta: timedelta | None = None,
) -> str:
    payload.update({TOKEN_TYPE_FIELD: token_type})
    return encode_jwt(payload, expire_delta)


def encode_jwt(
        payload: dict[str, Any],
        expire_delta: timedelta | None = None,
) -> str:
    to_encode = payload.copy()
    now = datetime.now(timezone.utc)
    if expire_delta:
        expire = now + expire_delta
    else:
        expire = now + timedelta(minutes=settings.jwt.access_token_expire_minutes)
    to_encode.update(exp=expire, iat=now)
    encoded = jwt.encode(
        to_encode,
        settings.jwt.secret_key,
        algorithm=settings.jwt.algorithm
    )
    return encoded


def decode_jwt(token: str) -> dict[str, Any]:
    decoded = jwt.decode(
        token,
        settings.jwt.secret_key,
        algorithms=[settings.jwt.algorithm],
    )
    return decoded
