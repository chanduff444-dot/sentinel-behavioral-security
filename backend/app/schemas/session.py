from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class SessionBase(BaseModel):
    user_id: int
    session_id: str
    status: str = "active"
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class SessionCreate(SessionBase):
    pass


class SessionRead(SessionBase):
    id: int
    started_at: datetime
    last_activity_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SessionUpdate(BaseModel):
    status: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
