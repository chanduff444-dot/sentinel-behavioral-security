from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from models import Event, Alert, UserSession
from typing import Any, Dict, Optional


def create_event(
    db: Session,
    user_id: int,
    event_type: str,
    payload: Dict[str, Any],
    session_id: Optional[str] = None
) -> Event:
    if session_id:
        session = db.query(UserSession).filter(
            UserSession.session_id == session_id,
            UserSession.user_id == user_id,
            UserSession.is_active == True
        ).first()
        if not session:
            raise ValueError("Invalid or inactive session")
    
    event = Event(
        user_id=user_id,
        event_type=event_type,
        payload=payload,
        session_id=session_id
    )
    db.add(event)
    db.flush()
    
    # 1. First-time event type
    existing_event_types = db.query(Event.event_type).filter(
        Event.user_id == user_id,
        Event.id != event.id
    ).distinct().all()
    existing_types = {et[0] for et in existing_event_types}
    
    if event_type not in existing_types:
        create_alert(
            db=db,
            user_id=user_id,
            alert_type="first_time_event",
            severity="medium",
            description=f"First time event type '{event_type}' for user {user_id}",
            event_id=event.id
        )
    
    # 2. High velocity
    five_min_ago = datetime.utcnow() - timedelta(minutes=5)
    recent_event_count = db.query(Event).filter(
        Event.user_id == user_id,
        Event.timestamp >= five_min_ago
    ).count()
    
    if recent_event_count > 10:
        create_alert(
            db=db,
            user_id=user_id,
            alert_type="high_velocity",
            severity="high",
            description=f"High velocity: {recent_event_count} events in 5 minutes",
            event_id=event.id
        )
    
    # 3. Off-hours
    event_hour = event.timestamp.hour
    if 1 <= event_hour < 5:
        create_alert(
            db=db,
            user_id=user_id,
            alert_type="off_hours_activity",
            severity="low",
            description=f"Off-hours activity at {event.timestamp.isoformat()}",
            event_id=event.id
        )
    
    db.commit()
    db.refresh(event)
    return event


def create_alert(
    db: Session,
    user_id: int,
    alert_type: str,
    severity: str,
    description: str,
    event_id: Optional[int] = None
) -> Alert:
    alert = Alert(
        user_id=user_id,
        alert_type=alert_type,
        severity=severity,
        description=description,
        event_id=event_id,
        is_resolved=False
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
