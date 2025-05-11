from typing import Annotated

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import (
    OAuth2PasswordRequestForm,
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from starlette import status

from src.core.dependency import db_dependency, user_dependency
from src.repository import users as user_repository
from src.schemas.auth import TokenSchema
from src.schemas.users import UserSchema, UserCreateSchema
from src.services import auth as auth_service

router = APIRouter(prefix="/auth", tags=["auth"])

security = HTTPBearer()


@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def create_account_via_email(
        body: UserCreateSchema,
        db: db_dependency,
):
    user_model = await user_repository.get_user_by_email(db, body.email)
    if user_model is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Account already exists.",
        )
    body.password = auth_service.hash_password(body.password)
    await user_repository.create_user(db, body)


@router.post("/login")
async def login_via_email_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: db_dependency,
):
    user_model = await auth_service.authenticate_user(db, form_data.username, form_data.password)
    if user_model is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
        )
    access_token = auth_service.create_access_token(user_model)
    refresh_token = auth_service.create_refresh_token(user_model)

    await user_repository.update_refresh_token(db, user_model.email, refresh_token)

    return TokenSchema(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=TokenSchema, response_model_exclude_none=True)
async def refresh_access_token(
        credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
        db: db_dependency,
):
    token = credentials.credentials
    email = auth_service.decode_refresh_token(token)

    user_model = await user_repository.get_user_by_email(db, email)
    if user_model is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate user."
        )
    if user_model.refresh_token != token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token."
        )
    access_token = auth_service.create_access_token(user_model)

    return TokenSchema(access_token=access_token)


@router.get("/users/me", response_model=UserSchema)
async def read_users_me(current_user: user_dependency):
    return current_user
