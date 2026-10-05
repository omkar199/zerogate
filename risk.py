"""Risk engine: scores each login attempt from 0 to 100 using simple rules."""

ODD_HOURS = range(0, 6)  # 12 AM to 6 AM


def calculate_risk(is_new_ip, is_new_device, hour, recent_failed_logins):
    score = 0
    reasons = []

    if is_new_ip:
        score += 30
        reasons.append("New IP address (+30)")
    if is_new_device:
        score += 25
        reasons.append("Unknown device/browser (+25)")
    if hour in ODD_HOURS:
        score += 20
        reasons.append(f"Odd login time {hour}:00 (+20)")
    if recent_failed_logins >= 3:
        score += 25
        reasons.append(f"{recent_failed_logins} failed logins in last 15 min (+25)")

    return min(score, 100), reasons


def decide(score):
    if score < 30:
        return "ALLOW"
    if score <= 70:
        return "OTP"
    return "BLOCK"
