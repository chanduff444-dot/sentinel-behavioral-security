from datetime import datetime
from typing import Any, List, Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlalchemy.orm import Session

from .database import get_db
from .models import Event, User
from .risk import calculate_risk_score

app = FastAPI(title="Behavioral Cyber Platform API")


class UserCreate(BaseModel):
    email: str
    full_name: str


class UserRead(BaseModel):
    id: int
    email: str
    full_name: str

    model_config = ConfigDict(from_attributes=True)


class EventCreate(BaseModel):
    user_id: int
    event_type: str
    session_id: Optional[str] = None
    payload: Optional[dict[str, Any]] = None


class EventRead(BaseModel):
    id: int
    user_id: int
    event_type: str
    session_id: Optional[str] = None
    payload: Optional[Any] = None
    timestamp: datetime
    risk_score: Optional[float] = None

    model_config = ConfigDict(from_attributes=True)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/dependencies")
def health_deps(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except Exception as exc:
        return {"status": "degraded", "database": "error", "detail": str(exc)}


@app.post("/users", response_model=UserRead)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already exists")

    db_user = User(email=user.email, full_name=user.full_name)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.get("/users", response_model=List[UserRead])
def list_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(User).offset(skip).limit(limit).all()


@app.post("/events", response_model=EventRead)
def create_event(event: EventCreate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == event.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    now = datetime.utcnow()
    risk_score = calculate_risk_score(
        event_type=event.event_type,
        payload=event.payload,
        timestamp=now,
    )

    db_event = Event(
        user_id=event.user_id,
        event_type=event.event_type,
        session_id=event.session_id,
        payload=event.payload,
        timestamp=now,
        risk_score=risk_score,
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event


@app.get("/events", response_model=List[EventRead])
def list_events(
    user_id: Optional[int] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(Event)

    if user_id is not None:
        query = query.filter(Event.user_id == user_id)

    if event_type is not None:
        query = query.filter(Event.event_type == event_type)

    return query.order_by(Event.timestamp.desc()).limit(limit).all()
