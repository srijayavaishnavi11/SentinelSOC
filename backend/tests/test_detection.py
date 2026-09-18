from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base, SecurityEvent
from app.risk_scoring import calculate_risk_score
from app.detection.rules import(
    detect_sql_injection,
    detect_xss,
    detect_brute_force,
    detect_port_scan
)

def create_test_db():
    engine=create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal=sessionmaker(bind=engine)
    return SessionLocal()
def test_sql_injection_detected():
    result=detect_sql_injection("' OR 1=1")
    assert result["detected"] is True
    assert result["threat_type"]=="SQL Injection"
def test_sql_injection_false_positive():
    result=detect_sql_injection("Order ID: 123--456")
    assert result["detected"] is False
def test_xss_detected():
    result = detect_xss("<script>alert('XSS')</script>")
    assert result["detected"] is True
    assert result["threat_type"] == "Cross-Site Scripting (XSS)"
def test_xss_false_positive():
    result = detect_xss("This is a normal web request")
    assert result["detected"] is False
def test_brute_force_detected():
    db=create_test_db()
    for _ in range(5):
        event=SecurityEvent(
            event_type="LOGIN_FAILED",
            source_ip="10.10.10.50",
            username="testuser",
            severity="LOW",
            message="Failed Login",
            timestamp=datetime.now(),
        )
        db.add(event)
    db.commit()
    result=detect_brute_force(
        db,
        "10.10.10.50",
        "testuser"
    )
    assert result["detected"] is True
    assert result["threat_type"]=="Brute Force Attack"
    assert result["attempts"]==5
    db.close()
def test_port_scan_detected():
    db=create_test_db()
    ports=[21,22,23,25,53,80,110,135,443,445]
    for port in ports:
        event=SecurityEvent(
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
    result=detect_port_scan(
        db,
        "10.10.10.80"
    )
    assert result["detected"] is True
    assert result["threat_type"]=="Port Scan"
    assert result["unique_ports"]==10
    db.close()
def test_sql_injection_risk_score():
    result=calculate_risk_score("SQL Injection")
    assert result["risk_score"]==60
    assert result["severity"]=="HIGH"
def test_xss_risk_score():
    result=calculate_risk_score("Cross-Site Scripting (XSS)")
    assert result["risk_score"]==50
    assert result["severity"]=="MEDIUM"
def test_port_scan_risk_score():
    result=calculate_risk_score("Port Scan")
    assert result["risk_score"]==50
    assert result["severity"]=="MEDIUM"
def test_brute_force_medium_risk_score():
    result = calculate_risk_score(
        "Brute Force Attack",
        attempts=5
    )
    assert result["risk_score"] == 40
    assert result["severity"] == "MEDIUM"
def test_brute_force_risk_score():
    result=calculate_risk_score("Brute Force Attack",attempts=20)
    assert result["risk_score"]==80
    assert result["severity"]=="CRITICAL"
def test_privileged_user_risk_score():
    result=calculate_risk_score("SQL Injection",username="admin")
    assert result["risk_score"]==70
    assert result["severity"]=="HIGH"

