from datetime import datetime
from  fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.main import app, get_db
from app.models import Base, SecurityEvent

engine=create_engine(
    "sqlite://",
    connect_args={"check_same_thread":False},
    poolclass=StaticPool,
    )
TestingSessionLocal=sessionmaker(bind=engine)
Base.metadata.create_all(bind=engine)
def override_get_db():
    db=TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
app.dependency_overrides[get_db]=override_get_db
client=TestClient(app)
def test_health_check():
    response=client.get("/health")
    assert response.status_code==200
    assert response.json()["status"]=="healthy"
def test_create_normal_security_event():
    payload={
        "event_type":"LOGIN_SUCCESS",
        "source_ip":"10.10.10.20",
        "username":"testuser",
        "severity":"LOW",
        "message":"Successful login",
    }
    response=client.post("/events",json=payload)
    assert response.status_code==200
    data=response.json()
    assert data["message"]=="Security event stored, no threat detected"
    assert "event_id" in data
    assert data["detection"]["brute_force"]["detected"] is False
    assert data["detection"]["sql_injection"]["detected"] is False
    assert data["detection"]["xss"]["detected"] is False
def test_create_sql_injection_event():
    payload = {
        "event_type": "WEB_REQUEST",
        "source_ip": "10.10.10.30",
        "username": "attacker",
        "severity": "HIGH",
        "message": "' OR 1=1 --",
    }
    response = client.post("/events", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Security event stored and SQL injection detected"
    assert "event_id" in data
    assert "alert_id" in data
    assert data["risk_score"] == 60
    assert data["severity"] == "HIGH"
    assert data["detection"]["detected"] is True
    assert data["detection"]["threat_type"] == "SQL Injection"
def test_brute_force_api_detection():
    db = TestingSessionLocal()
    for _ in range(5):
        event = SecurityEvent(
            event_type="LOGIN_FAILED",
            source_ip="10.10.10.50",
            username="testuser",
            severity="LOW",
            message="Failed login attempt",
            timestamp=datetime.now(),
        )
        db.add(event)
    db.commit()
    # Verify the test database actually contains the 5 events
    count = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "LOGIN_FAILED",
        SecurityEvent.source_ip == "10.10.10.50",
        SecurityEvent.username == "testuser",
    ).count()
    assert count == 5
    db.close()
    payload = {
        "event_type": "LOGIN_FAILED",
        "source_ip": "10.10.10.50",
        "username": "testuser",
        "severity": "LOW",
        "message": "Failed login attempt",
    }
    response = client.post("/events", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Security event stored and threat detected"
    assert "alert_id" in data
    assert data["risk_score"] == 40
    assert data["severity"] == "MEDIUM"
    assert data["detection"]["detected"] is True
    assert data["detection"]["threat_type"] == "Brute Force Attack"
    assert data["detection"]["attempts"] == 5
def test_port_scan_api_detection():
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 443, 445]

    db = TestingSessionLocal()

    for port in ports:
        event = SecurityEvent(
            event_type="PORT_CONNECTION",
            source_ip="10.10.10.80",
            username="scanner",
            severity="LOW",
            message="Connection attempt",
            destination_port=port,
            timestamp=datetime.now(),
        )
        db.add(event)

    db.commit()

    count = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "PORT_CONNECTION",
        SecurityEvent.source_ip == "10.10.10.80",
        SecurityEvent.destination_port.isnot(None),
    ).count()

    assert count == 10

    db.close()

    payload = {
        "event_type": "PORT_CONNECTION",
        "source_ip": "10.10.10.80",
        "username": "scanner",
        "severity": "LOW",
        "message": "Connection attempt",
        "destination_port": 8080,
    }

    response = client.post("/events", json=payload)

    assert response.status_code == 200

    data = response.json()

    assert data["message"] == "Security event stored and Port Scan detected"
    assert "alert_id" in data
    assert data["risk_score"] == 50
    assert data["severity"] == "MEDIUM"
    assert data["detection"]["detected"] is True
    assert data["detection"]["threat_type"] == "Port Scan"
    assert data["detection"]["unique_ports"] == 10