from datetime import datetime
from pydantic import BaseModel


class EventBase(BaseModel):
    event_type: str
    session_id: str | None = None
    payload: str | None = None


class EventCreate(EventBase):
    user_id: int


class EventResponse(EventBase):
    id: int
    user_id: int
    timestamp: datetime

    model_config = {"from_attributes": True}
