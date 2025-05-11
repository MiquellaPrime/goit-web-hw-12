from datetime import date

from pydantic import BaseModel, ConfigDict, EmailStr


class ContactBaseSchema(BaseModel):
    first_name: str
    last_name:  str
    phone:      str
    email:      EmailStr | None = None
    birth_date: date | None = None
    extra:      str | None = None


class ContactSchema(ContactBaseSchema):
    model_config = ConfigDict(from_attributes=True)

    id: int


class ContactCreateSchema(ContactBaseSchema):
    pass


class ContactUpdateSchema(ContactBaseSchema):
    pass


class ContactBirthDateUpdateSchema(BaseModel):
    birth_date: date
