from sqlalchemy import select, func
from sqlalchemy.orm import Session

from src.database.models import ContactORM
from src.schemas.contacts import (
    ContactCreateSchema,
    ContactUpdateSchema,
    ContactBirthDateUpdateSchema,
)
from src.schemas.filters import FilterParams


async def get_contacts(db: Session, user_id: int, fp: FilterParams) -> list[ContactORM]:
    stmt = select(ContactORM).filter_by(user_id=user_id)

    if fp.first_name:
        stmt = stmt.filter_by(first_name=fp.first_name)
    if fp.last_name:
        stmt = stmt.filter_by(last_name=fp.last_name)
    if fp.email:
        stmt = stmt.filter_by(email=fp.email)
    if fp.phone:
        stmt = stmt.filter_by(phone=fp.phone)

    return db.scalars(stmt).all()


async def get_contact_by_id(db: Session, user_id: int, contact_id: int) -> ContactORM | None:
    stmt = select(ContactORM).filter_by(id=contact_id, user_id=user_id)
    return db.execute(stmt).first()


async def get_upcoming_birthdays(db: Session, user_id: int, date_list: list[str]) -> list[ContactORM]:
    stmt = select(ContactORM).where(
        ContactORM.user_id == user_id,
        func.to_char(ContactORM.birth_date, "MM-DD").in_(date_list)
    )
    return db.scalars(stmt).all()


async def create_contact(db: Session, user_id: int, body: ContactCreateSchema):
    contact_model = ContactORM(
        first_name=body.first_name,
        last_name=body.last_name,
        phone=body.phone,
        email=body.email,
        birth_date=body.birth_date,
        extra=body.extra,
        user_id=user_id
    )
    db.add(contact_model)
    db.commit()


async def update_contact(
        db: Session,
        user_id: int,
        contact_id: int,
        body: ContactUpdateSchema
) -> ContactORM | None:
    stmt = select(ContactORM).filter_by(id=contact_id, user_id=user_id)
    contact_model = db.execute(stmt).scalar()

    if contact_model is not None:
        contact_model.first_name = body.first_name
        contact_model.last_name = body.last_name
        contact_model.email = body.email
        contact_model.phone = body.phone
        contact_model.birth_date = body.birth_date
        contact_model.extra = body.extra
        db.commit()

    return contact_model


async def update_birth_date(
        db: Session,
        user_id: int,
        contact_id: int,
        body: ContactBirthDateUpdateSchema
) -> ContactORM | None:
    stmt = select(ContactORM).filter_by(id=contact_id, user_id=user_id)
    contact_model = db.execute(stmt).scalar()

    if contact_model is not None:
        contact_model.birth_date = body.birth_date
        db.commit()

    return contact_model


async def delete_contact(db: Session, user_id: int, contact_id: int) -> ContactORM | None:
    stmt = select(ContactORM).filter_by(id=contact_id, user_id=user_id)
    contact_model = db.execute(stmt).scalar()

    if contact_model is not None:
        db.delete(contact_model)
        db.commit()

    return contact_model
