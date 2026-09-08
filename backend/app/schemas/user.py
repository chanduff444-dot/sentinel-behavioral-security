from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    email: EmailStr
    full_name: str | None = None


class UserCreate(UserBase):
    pass


class UserResponse(UserBase):
    id: int

    model_config = {"from_attributes": True}
