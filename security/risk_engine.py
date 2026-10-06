
def calculate_risk(
    new_device=False,
    new_ip=False,
    unusual_time=False,
    failed_attempts=0,
    unusual_location=False
):
    score = 0
    reasons = []

    if new_device:
        score += 25
        reasons.append("Login from a new device (+25)")

    if new_ip:
        score += 20
        reasons.append("Login from a new IP address (+20)")

    if unusual_time:
        score += 15
        reasons.append("Login at an unusual time (+15)")

    if failed_attempts >= 5:
        score += 30
        reasons.append(
            f"{failed_attempts} failed login attempts in the last 24 hours (+30)"
        )
    elif failed_attempts >= 3:
        score += 20
        reasons.append(
            f"{failed_attempts} failed login attempts in the last 24 hours (+20)"
        )
    elif failed_attempts >= 1:
        score += 10
        reasons.append(
            f"{failed_attempts} failed login attempt(s) in the last 24 hours (+10)"
        )

    if unusual_location:
        score += 25
        reasons.append("Login from an unusual location (+25)")

    score = min(score, 100)

    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons.append("No risk indicators detected")

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }