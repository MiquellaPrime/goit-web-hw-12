from sqlalchemy import Column, Integer, String, DateTime, Date, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

from src.utils.common import current_time

Base = declarative_base()


class UserORM(Base):
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True)
    email           = Column(String(25), nullable=False, unique=True)
    hashed_password = Column(String, nullable=False)
    first_name      = Column(String(15), nullable=False)
    last_name       = Column(String(15))
    created_at      = Column(DateTime, default=current_time)
    refresh_token   = Column(String, nullable=True)

    contacts = relationship("ContactORM", backref="user")


class ContactORM(Base):
    __tablename__ = "contacts"

    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    first_name = Column(String(15), nullable=False)
    last_name  = Column(String(15))
    phone      = Column(String(15), nullable=False, unique=True)
    email      = Column(String(25), nullable=True, unique=True)
    birth_date = Column(Date, nullable=True)
    extra      = Column(String(150), nullable=True)
