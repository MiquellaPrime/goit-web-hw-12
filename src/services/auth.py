from datetime import timedelta
from typing import Annotated

from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session
from starlette import status
from passlib.context import CryptContext

from src.core.config import TOKEN_TYPE_FIELD, ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE
from src.core.settings import settings
from src.database.db import get_db
from src.database.models import UserORM
from src.repository import users as user_repository
from src.utils import auth as auth_utils

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(user_model: UserORM) -> str:
    payload = {
        "sub": user_model.email,
    }
    return auth_utils.create_jwt(ACCESS_TOKEN_TYPE, payload)


def create_refresh_token(user_model: UserORM) -> str:
    payload = {
        "sub": user_model.email,
    }
    expire_delta = timedelta(days=settings.jwt.refresh_token_expire_days)
    return auth_utils.create_jwt(REFRESH_TOKEN_TYPE, payload, expire_delta)


def decode_refresh_token(token: str) -> str:
    try:
        payload = auth_utils.decode_jwt(token)
        token_type = payload[TOKEN_TYPE_FIELD]
        if token_type == REFRESH_TOKEN_TYPE:
            return payload["sub"]
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token type.")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials.")


async def authenticate_user(db: Session, email: str, password: str) -> UserORM | None:
    user_model = await user_repository.get_user_by_email(db, email)
    if user_model is None:
        return None
    if verify_password(password, user_model.hashed_password):
        return None
    return user_model


async def get_current_user(
        token: Annotated[str, Depends(oauth2_scheme)],
        db: Annotated[Session, Depends(get_db)],
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = auth_utils.decode_jwt(token)
        if payload[TOKEN_TYPE_FIELD] == ACCESS_TOKEN_TYPE:
            email = payload["sub"]
            if email is None:
                raise credentials_exception
        else:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user_model = await user_repository.get_user_by_email(db, email)
    if user_model is None:
        raise credentials_exception
    return user_model
