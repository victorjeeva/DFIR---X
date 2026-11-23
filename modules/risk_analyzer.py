def calculate_risk(log_result=None, ioc_result=None, integrity_status=None):
    """
    Calculate an automated DFIR incident risk score
    using network/log findings, IOC findings,
    and evidence integrity status.
    """

    log_result = log_result or {}
    ioc_result = ioc_result or {}

    score = 0
    reasons = []

    # -----------------------------
    # Network / Log Risk
    # -----------------------------

    failed_logins = log_result.get("failed_logins", 0)

    if failed_logins >= 5:
        score += 30
        reasons.append(
            f"{failed_logins} failed login attempts detected"
        )

    elif failed_logins >= 3:
        score += 20
        reasons.append(
            f"{failed_logins} failed login attempts detected"
        )

    successful_logins = log_result.get("successful_logins", 0)

    if successful_logins > 0 and failed_logins >= 3:
        score += 20
        reasons.append(
            "Successful login occurred after repeated failed attempts"
        )

    repeated_ips = log_result.get("repeated_ips", {})

    if repeated_ips:
        score += 15

        for ip, count in repeated_ips.items():
            reasons.append(
                f"Repeated source IP detected: {ip} ({count} occurrences)"
            )

    connection_events = log_result.get("connection_events", 0)

    if connection_events >= 3:
        score += 10
        reasons.append(
            f"{connection_events} network connection events detected"
        )

    # -----------------------------
    # IOC Risk
    # -----------------------------

    ip_count = len(
        ioc_result.get("ip_addresses", [])
    )

    url_count = len(
        ioc_result.get("urls", [])
    )

    hash_count = len(
        ioc_result.get("hashes", [])
    )

    if ip_count > 0:
        score += 10
        reasons.append(
            f"{ip_count} IP IOC(s) detected"
        )

    if url_count > 0:
        score += 15
        reasons.append(
            f"{url_count} URL IOC(s) detected"
        )

    if hash_count > 0:
        score += 20
        reasons.append(
            f"{hash_count} hash IOC(s) detected"
        )

    # -----------------------------
    # Evidence Integrity
    # -----------------------------

    if integrity_status == "Mismatch":
        score += 30
        reasons.append(
            "Evidence integrity mismatch detected"
        )

    # -----------------------------
    # Risk Level
    # -----------------------------

    if score >= 70:
        risk_level = "CRITICAL"

    elif score >= 45:
        risk_level = "HIGH"

    elif score >= 20:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }
