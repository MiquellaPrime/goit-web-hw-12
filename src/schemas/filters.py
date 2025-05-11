from pydantic import BaseModel, EmailStr


class FilterParams(BaseModel):
    first_name: str | None = None
    last_name:  str | None = None
    email:      EmailStr | None = None
    phone:      str | None = None
