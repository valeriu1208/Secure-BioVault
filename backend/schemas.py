import uuid
from pydantic import BaseModel, Field


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=12, max_length=256)


class RoleUpdateIn(BaseModel):
    new_role: str = Field(pattern="^(PATIENT|DOCTOR|ADMIN|RESEARCHER)$")


class RoleRequestIn(BaseModel):
    req_role: str = Field(pattern="^(DOCTOR|RESEARCHER)$")
    justification: str = Field(max_length=500)


class ResolveRequestIn(BaseModel):
    status: str = Field(pattern="^(APPROVED|REJECTED)$")


class DeleteAccountIn(BaseModel):
    password: str = Field(min_length=1)


class UpdateUserActiveStatusIn(BaseModel):
    is_active: bool


class FileAccessRequestIn(BaseModel):
    file_id: uuid.UUID
    reason: str = ""


class GrantFileAccessIn(BaseModel):
    target_user_id: uuid.UUID


class GrantFileRoleAccessIn(BaseModel):
    role_name: str = Field(pattern="^(DOCTOR|RESEARCHER)$")


class RequestStatusUpdate(BaseModel):
    status: str


class DirectGrantIn(BaseModel):
    target_user_id: uuid.UUID