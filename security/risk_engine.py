def calculate_risk(
    new_device=False,
    new_ip=False,
    unusual_time=False,
    failed_attempts=0,
    unusual_location=False
):
    risk_score = 0
    reasons = []

    # New device
    if new_device:
        risk_score += 15
        reasons.append("Login from a new device")

    # New IP
    if new_ip:
        risk_score += 10
        reasons.append("Login from a new IP address")

    # Unusual login time
    if unusual_time:
        risk_score += 15
        reasons.append("Login at an unusual time")

    # Failed login attempts
    if failed_attempts >= 3:
        risk_score += 25
        reasons.append(
            "Multiple failed login attempts"
        )

    # Unusual location
    if unusual_location:
        risk_score += 20
        reasons.append(
            "Unusual login location"
        )

    # Risk level
    if risk_score <= 20:
        risk_level = "LOW"

    elif risk_score <= 50:
        risk_level = "MEDIUM"

    else:
        risk_level = "HIGH"

    return {
        "score": risk_score,
        "level": risk_level,
        "reasons": reasons
    }