from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
from app import models
from app.database import engine, SessionLocal, get_db

# Import detection modules
from app.api.anomaly_detector import detect_anomalies
from app.threat_intel import threat_intel
from app.api.network_monitor import network_monitor

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Behavioral Cybersecurity API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ User Endpoints ============
@app.post("/api/users")
def create_user(username: str, email: str, password: str, role: str = "user", db: Session = Depends(get_db)):
    from sqlalchemy.exc import IntegrityError
    import hashlib
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    
    user = models.User(username=username, email=email, hashed_password=hashed_pw, role=role)
    try:
        db.add(user)
        db.commit()
        db.refresh(user)
        return {"id": user.id, "username": user.username, "email": user.email}
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Username or email already exists")

@app.get("/api/users")
def get_users(db: Session = Depends(get_db)):
    return db.query(models.User).all()

@app.get("/api/users/risk-summary")
def get_all_users_risk(db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    risk_profiles = []
    
    for user in users:
        events = db.query(models.Event).filter(models.Event.user_id == user.id).all()
        alerts = db.query(models.Alert).filter(models.Alert.user_id == user.id).all()
        
        total_events = len(events)
        avg_risk = sum([e.risk_score for e in events if e.risk_score]) / total_events if total_events > 0 else 0
        open_alerts = len([a for a in alerts if a.status == models.AlertStatus.OPEN])
        
        if avg_risk >= 4.0 or open_alerts >= 5:
            risk_level = "high"
        elif avg_risk >= 2.5 or open_alerts >= 2:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        risk_profiles.append({
            "user_id": user.id,
            "username": user.username,
            "avg_risk_score": round(avg_risk, 2),
            "open_alerts": open_alerts,
            "risk_level": risk_level
        })
    
    risk_profiles.sort(key=lambda x: x['avg_risk_score'], reverse=True)
    return risk_profiles

@app.get("/api/users/{user_id}/risk-profile")
def get_user_risk_profile(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    events = db.query(models.Event).filter(models.Event.user_id == user_id).all()
    total_events = len(events)
    avg_risk_score = sum([e.risk_score for e in events if e.risk_score]) / total_events if total_events > 0 else 0
    
    alerts = db.query(models.Alert).filter(models.Alert.user_id == user_id).all()
    open_alerts = len([a for a in alerts if a.status == models.AlertStatus.OPEN])
    
    if avg_risk_score >= 4.0 or open_alerts >= 5:
        risk_level = "high"
    elif avg_risk_score >= 2.5 or open_alerts >= 2:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    recent_events = db.query(models.Event).filter(
        models.Event.user_id == user_id,
        models.Event.timestamp >= seven_days_ago
    ).all()
    
    daily_risk = {}
    for event in recent_events:
        day = event.timestamp.strftime('%Y-%m-%d')
        if day not in daily_risk:
            daily_risk[day] = []
        if event.risk_score:
            daily_risk[day].append(event.risk_score)
    
    daily_avg = {day: sum(scores)/len(scores) for day, scores in daily_risk.items() if scores}
    
    return {
        "user_id": user_id,
        "username": user.username,
        "total_events": total_events,
        "avg_risk_score": round(avg_risk_score, 2),
        "open_alerts": open_alerts,
        "risk_level": risk_level,
        "daily_risk_trend": daily_avg
    }

# ============ Event Endpoints ============
@app.post("/api/events")
def create_event(user_id: int, event_type: str, risk_score: Optional[float] = None, db: Session = Depends(get_db)):
    event = models.Event(user_id=user_id, event_type=event_type, risk_score=risk_score)
    db.add(event)
    db.commit()
    db.refresh(event)
    
    # Detect anomalies
    anomalies = detect_anomalies(db, user_id, event)
    
    return {"id": event.id, "user_id": user_id, "event_type": event_type, "risk_score": risk_score, "anomalies": anomalies}

@app.get("/api/events")
def get_events(limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.Event).order_by(models.Event.timestamp.desc()).limit(limit).all()

# ============ Alert Endpoints ============
@app.get("/api/alerts")
def get_alerts(limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.Alert).order_by(models.Alert.created_at.desc()).limit(limit).all()

@app.put("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, status: models.AlertStatus, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = status
    db.commit()
    return {"message": "Alert status updated", "alert_id": alert_id, "status": status.value}

# ============ Session Endpoints ============
@app.get("/api/sessions")
def get_sessions(db: Session = Depends(get_db)):
    return db.query(models.Session).all()

@app.post("/api/sessions")
def create_session(user_id: int, session_token: str, ip_address: str, user_agent: str = "", db: Session = Depends(get_db)):
    session = models.Session(user_id=user_id, session_token=session_token, ip_address=ip_address, user_agent=user_agent)
    db.add(session)
    db.commit()
    db.refresh(session)
    return session

# ============ IoC Detection Endpoints ============
@app.get("/api/ioc/check-ip/{ip_address}")
def check_ip(ip_address: str, db: Session = Depends(get_db)):
    result = threat_intel.check_ip_reputation(ip_address)
    
    if result.get("is_malicious"):
        alert = models.Alert(
            user_id=1,
            severity="high" if result.get("confidence", 0) > 75 else "medium",
            reason=f"IoC Detection: Malicious IP {ip_address} (confidence: {result.get('confidence', 0)}%)"
        )
        db.add(alert)
        db.commit()
    
    return result

@app.get("/api/ioc/check-url")
def check_url(url: str, db: Session = Depends(get_db)):
    result = threat_intel.check_url_threat(url)
    
    if result.get("is_malicious"):
        alert = models.Alert(
            user_id=1,
            severity="high" if result.get("confidence", 0) > 75 else "medium",
            reason=f"IoC Detection: Malicious URL detected (type: {result.get('threat_type')})"
        )
        db.add(alert)
        db.commit()
    
    return result

@app.get("/api/ioc/check-file/{file_hash}")
def check_file(file_hash: str, db: Session = Depends(get_db)):
    result = threat_intel.check_file_hash(file_hash)
    
    if result.get("is_malicious"):
        alert = models.Alert(
            user_id=1,
            severity="high",
            reason=f"IoC Detection: Malicious file detected (family: {result.get('malware_family')})"
        )
        db.add(alert)
        db.commit()
    
    return result

# ============ Network & Threat Intel ============
@app.get("/api/network/status")
def get_network_status():
    return network_monitor.get_network_summary()

@app.get("/api/threat-intel/summary")
def get_threat_summary():
    return threat_intel.get_threat_summary()

# ============ Health Check ============
@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# Additional alert update endpoint (accepts JSON body)
@app.put("/alerts/{alert_id}")
def update_alert(alert_id: int, update_data: dict, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    if "status" in update_data:
        alert.status = update_data["status"]
    db.commit()
    db.refresh(alert)
    return {"message": "Alert updated", "alert_id": alert_id, "status": alert.status.value}
