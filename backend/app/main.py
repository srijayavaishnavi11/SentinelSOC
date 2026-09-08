from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from .database import engine, SessionLocal
from .models import Base, SecurityEvent, Alert
from .schemas import SecurityEventCreate
from .risk_scoring import calculate_risk_score
from .detection.rules import (
    detect_brute_force, 
    detect_sql_injection, 
    detect_xss,
    detect_port_scan)


Base.metadata.create_all(bind=engine)
app = FastAPI(
    title="SentinelSOC",
    description="Real-Time Security Operations Center Platform",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def home():
    return {
        "message": "SentinelSOC is running",
        "status": "online"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }

@app.post("/events")
def create_security_event(
    event: SecurityEventCreate,
    db: Session = Depends(get_db)
):
    new_event = SecurityEvent(
        event_type=event.event_type,
        source_ip=event.source_ip,
        username=event.username,
        destination_port=event.destination_port,
        severity=event.severity,
        message=event.message
    )
    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    detection_result = detect_brute_force(
        db,
        event.source_ip,
        event.username
    )
    if detection_result["detected"]:
        risk_result = calculate_risk_score(
            detection_result["threat_type"],
            detection_result["attempts"],
            detection_result["username"]
        )
        alert_time_window = datetime.now() - timedelta(seconds=60)
        existing_alert = db.query(Alert).filter(
            Alert.threat_type == detection_result["threat_type"],
            Alert.source_ip == detection_result["source_ip"],
            Alert.username == detection_result["username"],
            Alert.status == "open",
            Alert.created_at >= alert_time_window
        ).first()

        if existing_alert is not None:
            return {
                "message": "Security event stored, threat already detected",
                "event_id": new_event.id,
                "alert_id": existing_alert.id,
                "risk_score": existing_alert.risk_score,
                "severity": existing_alert.severity,
                "detection": detection_result
            }

        new_alert = Alert(
            threat_type=detection_result["threat_type"],
            source_ip=detection_result["source_ip"],
            username=detection_result["username"],
            severity=risk_result["severity"],
            risk_score=risk_result["risk_score"],
            message=detection_result["message"],
            status="open",
        )

        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        return {
        "message": "Security event stored and threat detected",
        "event_id": new_event.id,
        "alert_id": new_alert.id,
        "risk_score": risk_result["risk_score"],
        "severity": risk_result["severity"],
        "detection": detection_result
        }
    sql_detection_result = detect_sql_injection(event.message)
    if sql_detection_result["detected"]:
        risk_result = calculate_risk_score(
            sql_detection_result["threat_type"],
            username=event.username
        )
        new_alert = Alert(
            threat_type=sql_detection_result["threat_type"],
            source_ip=event.source_ip,
            username=event.username,
            severity=risk_result["severity"],
            risk_score=risk_result["risk_score"],
            message=sql_detection_result["message"],
            status="open"
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        return {
            "message": "Security event stored and SQL injection detected",
            "event_id": new_event.id,
            "alert_id": new_alert.id,
            "risk_score": risk_result["risk_score"],
            "severity": risk_result["severity"],
            "detection": sql_detection_result
        }
    xss_detection_result = detect_xss(event.message)
    if xss_detection_result["detected"]:
        risk_result = calculate_risk_score(
            xss_detection_result["threat_type"],
            username=event.username
        )
        new_alert = Alert(
            threat_type=xss_detection_result["threat_type"],
            source_ip=event.source_ip,
            username=event.username,
            severity=risk_result["severity"],
            risk_score=risk_result["risk_score"],
            message=xss_detection_result["message"],
            status="open"
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        return {
            "message": "Security event stored and XSS detected",
            "event_id": new_event.id,
            "alert_id": new_alert.id,
            "risk_score": risk_result["risk_score"],
            "severity": risk_result["severity"],
            "detection": xss_detection_result
        }
    port_scan_result = detect_port_scan(
        db,
        event.source_ip,
    )
    if port_scan_result["detected"]:
        risk_result = calculate_risk_score(
            port_scan_result["threat_type"],
            username=event.username
        )
        new_alert = Alert(
            threat_type=port_scan_result["threat_type"],
            source_ip=event.source_ip,
            username=event.username,
            severity=risk_result["severity"],
            risk_score=risk_result["risk_score"],
            message=port_scan_result["message"],
            status="open"
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        return {
            "message": "Security event stored and Port Scan detected",
            "event_id": new_event.id,
            "alert_id": new_alert.id,
            "risk_score": risk_result["risk_score"],
            "severity": risk_result["severity"],
            "detection": port_scan_result
        }
    return {
        "message": "Security event stored, no threat detected",
        "event_id": new_event.id,
        "detection": {
            "brute_force": detection_result,
            "sql_injection": sql_detection_result,
            "xss": xss_detection_result,
            "port_scan": port_scan_result
        }
    }

@app.get("/events")
def get_security_events(
    db: Session = Depends(get_db)
):
    events = db.query(SecurityEvent).all()
    return events

@app.get("/alerts")
def get_alerts(
    db: Session = Depends(get_db)
):
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
    return alerts

@app.patch("/alerts/{alert_id}")
def update_alert_status(
    alert_id: int,
    status: str,
    db: Session = Depends(get_db)
):
    allowed_statuses = {"open", "investigating", "resolved"}
    if status.lower() not in allowed_statuses:
        return {
            "error": f"Invalid status. Use: 'open, investigating, resolved'."
        }
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        return {
            "error": f"Alert with ID {alert_id} not found."
        }
    alert.status = status.lower()
    db.commit()
    db.refresh(alert)
    return {
        "message": f"Alert ID status updated",
        "alert_id": alert.id,
        "status": alert.status
    }

@app.get("/dashboard/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db)
):
    total_events=db.query(SecurityEvent).count()
    total_alerts=db.query(Alert).count()
    open_alerts=db.query(Alert).filter(Alert.status=="open").count()
    investigating_alerts=db.query(Alert).filter(Alert.status=="investigating").count()
    resolved_alerts=db.query(Alert).filter(Alert.status=="resolved").count()
    critical_alerts=db.query(Alert).filter(Alert.severity=="CRITICAL").count()
    high_alerts=db.query(Alert).filter(Alert.severity=="HIGH").count()
    medium_alerts=db.query(Alert).filter(Alert.severity=="MEDIUM").count()
    low_alerts=db.query(Alert).filter(Alert.severity=="LOW").count()
    return{
        "total_events": total_events,
        "total_alerts": total_alerts,
        "alerts_by_status": {
            "open": open_alerts,
            "investigating": investigating_alerts,
            "resolved": resolved_alerts
        },
        "alerts_by_severity": {
            "critical": critical_alerts,
            "high": high_alerts,
            "medium": medium_alerts,
            "low": low_alerts
        }
    }