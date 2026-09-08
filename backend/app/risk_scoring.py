def calculate_risk_score(
    threat_type: str,
    attempts: int=1,
    username: str | None = None
):
    score = 0
    threat_scores = {
        "Brute Force Attack": 20,
        "SQL Injection": 60,
        "XSS Attack": 50,
        "Port Scan": 50
    }

    score+= threat_scores.get(threat_type, 10)

    if threat_type == "Brute Force Attack":
        if attempts >= 20:
            score += 60
        elif attempts >= 10:
            score += 40
        elif attempts >= 5:
            score += 20

    # Privileged account
    privileged_users = {
        "admin",
        "root",
        "security"
    }

    if username and username.lower() in privileged_users:
        score += 10

    # Keep score within 0-100
    score = min(score, 100)

    # Convert score into severity
    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": score,
        "severity": severity
    }