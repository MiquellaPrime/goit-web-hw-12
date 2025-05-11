from datetime import date, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from starlette import status

from src.core.dependency import db_dependency, user_dependency
from src.repository import contacts as contacts_repository
from src.schemas.contacts import (
    ContactSchema,
    ContactCreateSchema,
    ContactUpdateSchema,
    ContactBirthDateUpdateSchema,
)
from src.schemas.filters import FilterParams

router = APIRouter(prefix="/contacts", tags=["contacts"])


@router.get("", response_model=list[ContactSchema])
async def read_all_contacts(
        user: user_dependency,
        db: db_dependency,
        filter_params: Annotated[FilterParams, Query()],
):
    contact_models = await contacts_repository.get_contacts(db, user.id, filter_params)
    if not contact_models:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Contacts not found.",
        )
    return contact_models


@router.get("/upcoming-birthdays", response_model=list[ContactSchema])
async def get_upcoming_birthdays(
        user: user_dependency,
        db: db_dependency,
        days: Annotated[int, Query(gt=0)] = 7,
):
    today = date.today()
    date_list = [(today + timedelta(days=i)).strftime("%m-%d") for i in range(days + 1)]

    contact_models = await contacts_repository.get_upcoming_birthdays(db, user.id, date_list)
    if not contact_models:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No contacts have birthdays in the next {days} day(s).",
        )
    return contact_models


@router.get("/{contact_id}", response_model=ContactSchema)
async def read_contact_by_id(
        user: user_dependency,
        db: db_dependency,
        contact_id: int
):
    contact_model = await contacts_repository.get_contact_by_id(db, user.id, contact_id)
    if contact_model is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Contact '{contact_id}' not found.",
        )
    return contact_model


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_contact(
        user: user_dependency,
        db: db_dependency,
        body: ContactCreateSchema
):
    await contacts_repository.create_contact(db, user.id, body)


@router.put("/{contact_id}", response_model=ContactSchema)
async def update_contact(
        user: user_dependency,
        db: db_dependency,
        contact_id: int,
        body: ContactUpdateSchema
):
    contact_model = await contacts_repository.update_contact(db, user.id, contact_id, body)
    if contact_model is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Contact '{contact_id}' not found.",
        )
    return contact_model


@router.patch("/{contact_id}", response_model=ContactSchema)
async def update_birth_date(
        user: user_dependency,
        db: db_dependency,
        contact_id: int,
        body: ContactBirthDateUpdateSchema,
):
    contact_model = await contacts_repository.update_birth_date(db, user.id, contact_id, body)
    if contact_model is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Contact '{contact_id}' not found.",
        )
    return contact_model


@router.delete("/{contact_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_contact(
        user: user_dependency,
        db: db_dependency,
        contact_id: int
):
    contact_model = await contacts_repository.delete_contact(db, user.id, contact_id)
    if contact_model is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Contact '{contact_id}' not found.",
        )
