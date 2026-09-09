import json
from datetime import datetime, timedelta
from typing import List, Optional, Any, Dict

from sqlalchemy.orm import Session

from app.models import Session as SessionModel, Alert, Event

# Config
MAX_ACTIVE_SESSIONS_PER_USER = 5
IDLE_TIMEOUT_MINUTES = 30


def _parse_payload(payload: Any) -> Dict[str, Any]:
    if payload is None:
        return {}
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        try:
            return json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}


def create_session(
    db: Session,
    user_id: int,
    session_id: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> SessionModel:
    now = datetime.utcnow()
    db_session = SessionModel(
        user_id=user_id,
        session_id=session_id,
        status="active",
        started_at=now,
        last_activity_at=now,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return db_session


def get_session_by_id(db: Session, session_id: str) -> Optional[SessionModel]:
    return db.query(SessionModel).filter(SessionModel.session_id == session_id).first()


def get_active_session(db: Session, session_id: str) -> Optional[SessionModel]:
    return (
        db.query(SessionModel)
        .filter(SessionModel.session_id == session_id, SessionModel.status == "active")
        .first()
    )


def list_user_sessions(db: Session, user_id: int, limit: int = 50) -> List[SessionModel]:
    return (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user_id)
        .order_by(SessionModel.started_at.desc())
        .limit(limit)
        .all()
    )


def list_active_sessions_for_user(db: Session, user_id: int) -> List[SessionModel]:
    return (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user_id, SessionModel.status == "active")
        .all()
    )


def update_session(
    db: Session,
    session: SessionModel,
    status: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> SessionModel:
    if status is not None:
        session.status = status
    if ip_address is not None:
        session.ip_address = ip_address
    if user_agent is not None:
        session.user_agent = user_agent
    session.last_activity_at = datetime.utcnow()
    db.commit()
    db.refresh(session)
    return session


def close_session(db: Session, session: SessionModel) -> SessionModel:
    session.status = "closed"
    session.last_activity_at = datetime.utcnow()
    db.commit()
    db.refresh(session)
    return session


def refresh_session_activity(db: Session, session: SessionModel) -> SessionModel:
    session.last_activity_at = datetime.utcnow()
    db.commit()
    db.refresh(session)
    return session


def enforce_max_sessions(db: Session, user_id: int, new_session: SessionModel) -> None:
    """
    Ensure user doesn't exceed MAX_ACTIVE_SESSIONS_PER_USER.
    If exceeded, close the oldest active session(s).
    """
    active = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user_id, SessionModel.status == "active")
        .order_by(SessionModel.started_at.asc())
        .all()
    )
    while len(active) > MAX_ACTIVE_SESSIONS_PER_USER:
        oldest = active.pop(0)
        if oldest.id == new_session.id:
            continue
        oldest.status = "closed"
        oldest.last_activity_at = datetime.utcnow()
    db.commit()


def close_idle_sessions(db: Session, user_id: Optional[int] = None) -> int:
    """
    Close sessions that have been inactive for longer than IDLE_TIMEOUT_MINUTES.
    Returns number of sessions closed.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=IDLE_TIMEOUT_MINUTES)
    q = (
        db.query(SessionModel)
        .filter(
            SessionModel.status == "active",
            SessionModel.last_activity_at < cutoff,
        )
    )
    if user_id is not None:
        q = q.filter(SessionModel.user_id == user_id)

    to_close = q.all()
    for s in to_close:
        s.status = "closed"
        s.last_activity_at = datetime.utcnow()
    if to_close:
        db.commit()
    return len(to_close)


def detect_session_anomaly(
    db: Session,
    session: SessionModel,
    event: Event,
) -> Optional[Alert]:
    """
    Simple anomaly detection:
    - If session IP or user_agent changes compared to previous events for this session,
      create a medium-severity alert.
    """
    # Get last event for this session
    last_event = (
        db.query(Event)
        .filter(Event.session_id == session.session_id, Event.id != event.id)
        .order_by(Event.timestamp.desc())
        .first()
    )
    if not last_event:
        return None

    prev_payload = _parse_payload(last_event.payload)
    curr_payload = _parse_payload(event.payload)

    prev_ip = prev_payload.get("ip")
    prev_ua = prev_payload.get("user_agent")

    curr_ip = curr_payload.get("ip")
    curr_ua = curr_payload.get("user_agent")

    reasons = []
    if prev_ip and curr_ip and prev_ip != curr_ip:
        reasons.append(f"IP changed from {prev_ip} to {curr_ip}")
    if prev_ua and curr_ua and prev_ua != curr_ua:
        reasons.append(f"User-Agent changed")

    if not reasons:
        return None

    reason = "; ".join(reasons)
    alert = Alert(
        user_id=session.user_id,
        event_id=event.id,
        severity="medium",
        reason=f"Suspicious session activity: {reason}",
        status="open",
    )
    return alert
