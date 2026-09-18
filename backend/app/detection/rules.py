from datetime import datetime, timedelta
from ..models import SecurityEvent

THREAT_BRUTE_FORCE="Brute Force Attack"
THREAT_SQL_INJECTION="SQL Injection"
THREAT_XSS="Cross-Site Scripting (XSS)"
THREAT_PORT_SCAN="Port Scan"

def detect_brute_force(
        db,
        source_ip: str,
        username: str| None
):
    '''Rule:
    5 or more failed login attempts from the same ip within last 60 sec.'''

    time_window=datetime.now()-timedelta(seconds=60)
    query=db.query(SecurityEvent).filter(
        SecurityEvent.event_type=="LOGIN_FAILED",
        SecurityEvent.source_ip==source_ip,
        SecurityEvent.timestamp>=time_window
    )
    if username:
        query=query.filter(SecurityEvent.username==username)
    failed_attempts=query.count()
    if failed_attempts>=5:
        return {
            "detected": True,
            "threat_type": THREAT_BRUTE_FORCE,
            "severity": "MEDIUM",
            "attempts": failed_attempts,
            "source_ip": source_ip,
            "username": username,
            "message": (
                f"Possible brute force attack detected: "
                f" {failed_attempts} failed login attempts "
                f"within 60 seconds from IP {source_ip}." )
        }
    return{
        "detected": False
    }

def detect_sql_injection(message:str):
    '''Rule:
     Detects SQL injection attempts based on common SQL keywords in the message.'''
    sql_patterns = [
        "' OR '1'='1",
    "' OR 1=1",
    '" OR "1"="1',
    '" OR 1=1',
    "UNION SELECT",
    "DROP TABLE",
    "INSERT INTO",
    "DELETE FROM",
    "UPDATE ",
    "xp_cmdshell",]
    message_lower = message.lower()
    matched_patterns = []
    for pattern in sql_patterns:
        if pattern.lower() in message_lower:
            matched_patterns.append(pattern)
    if matched_patterns:
        return {
            "detected": True,
            "threat_type": THREAT_SQL_INJECTION,
            "severity": "HIGH",
            "matched_patterns": matched_patterns,
            "message": (
                f"Possible SQL injection attempt detected: "
                f"Matched patterns: {', '.join(matched_patterns)}"
            )
        }
    return {
        "detected": False
    }

def detect_xss(message:str):
    '''Rule:
     Detects XSS attempts based on common XSS patterns in the message.'''
    xss_patterns = [
        "<script>", "</script>", "javascript:", "onerror=", "onload=","onclick=","<img src=","<iframe src=","<svg onload=","<body onload=","<input onfocus=","<form action=",
        "<img", "<iframe", "<svg", "<body", "<input", "<form","alert(", "prompt(", "confirm(", "<object", "<embed", "<applet", "<meta", "<link", "<style", "<base", "<audio", "<video", "<source", "<track", "<canvas", "<map", "<area", "<param", "<details", "<summary", "<menuitem","document.cookie", "document.location", "window.location", "eval(", "setTimeout(", "set"
    ]
    message_lower = message.lower()
    matched_patterns = []
    for pattern in xss_patterns:
        if pattern.lower() in message_lower:
            matched_patterns.append(pattern)
    if matched_patterns:
        return {
            "detected": True,
            "threat_type": THREAT_XSS,
            "severity": "MEDIUM",
            "matched_patterns": matched_patterns,
            "message": (
                f"Possible XSS attempt detected: "
                f"Matched patterns: {', '.join(matched_patterns)}"
            )
        }
    return {
        "detected": False
    }

def detect_port_scan(
        db,
        source_ip: str,
):
    '''Rule:
    10 or more connection attempts to different ports from the same ip within last 60 sec.'''

    time_window=datetime.now()-timedelta(seconds=60)
    events=db.query(SecurityEvent).filter(
        SecurityEvent.event_type=="PORT_CONNECTION",
        SecurityEvent.source_ip==source_ip,
        SecurityEvent.destination_port.isnot(None),
        SecurityEvent.timestamp>=time_window
    ).all()
    unique_ports=set()
    for event in events:
        unique_ports.add(event.destination_port)
    if len(unique_ports)>=10:
        return {
            "detected": True,
            "threat_type": THREAT_PORT_SCAN,
            "severity": "MEDIUM",
            "unique_ports": len(unique_ports),
            "source_ip": source_ip,
            "message": (
                f"Possible port scan detected: "
                f" {len(unique_ports)} unique ports accessed "
                f"within 60 seconds from IP {source_ip}." )
        }
    return{
        "detected": False,
        "unique_ports": len(unique_ports)
    }