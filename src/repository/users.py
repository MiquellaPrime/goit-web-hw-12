from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database.models import UserORM
from src.schemas.users import UserCreateSchema


async def get_user_by_email(db: Session, email: str) -> UserORM | None:
    stmt = select(UserORM).filter_by(email=email)
    return db.scalars(stmt).first()


async def create_user(db: Session, body: UserCreateSchema):
    user_model = UserORM(
        email=body.email,
        hashed_password=body.password,
        first_name=body.first_name,
        last_name=body.last_name,
    )
    db.add(user_model)
    db.commit()


async def update_refresh_token(db: Session, email: str, token: str):
    stmt = select(UserORM).filter_by(email=email)
    user_model = db.execute(stmt).scalar()

    user_model.refresh_token = token
    db.commit()
