import re
from pathlib import Path
from collections import Counter


def analyze_log(file_path):
    """
    Analyze a readable log/text evidence file and extract
    basic network and security events.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Log file not found: {file_path}"
        )

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    ip_pattern = (
        r"\b(?:25[0-5]|2[0-4]\d|1\d\d|"
        r"[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|"
        r"1\d\d|[1-9]?\d)){3}\b"
    )

    timestamp_pattern = (
        r"\b\d{4}-\d{2}-\d{2}"
        r"(?:[ T]\d{2}:\d{2}:\d{2})?\b"
    )

    username_pattern = r"\buser(?:name)?=([A-Za-z0-9_.@-]+)"

    port_pattern = r"\b(?:dst_port|port)=([0-9]{1,5})\b"

    ip_addresses = []
    timestamps = []
    usernames = []
    ports = []

    failed_logins = 0
    successful_logins = 0
    connection_events = 0

    event_lines = []

    for line in lines:

        ips = re.findall(ip_pattern, line)
        ip_addresses.extend(ips)

        times = re.findall(timestamp_pattern, line)
        timestamps.extend(times)

        users = re.findall(
            username_pattern,
            line,
            flags=re.IGNORECASE
        )
        usernames.extend(users)

        found_ports = re.findall(
            port_pattern,
            line,
            flags=re.IGNORECASE
        )
        ports.extend(found_ports)

        lower_line = line.lower()

        if "login_failed" in lower_line or "login failed" in lower_line:
            failed_logins += 1
            event_lines.append({
                "type": "LOGIN_FAILED",
                "line": line.strip()
            })

        if "login_success" in lower_line or "login success" in lower_line:
            successful_logins += 1
            event_lines.append({
                "type": "LOGIN_SUCCESS",
                "line": line.strip()
            })

        if "connection" in lower_line:
            connection_events += 1
            event_lines.append({
                "type": "CONNECTION",
                "line": line.strip()
            })

    ip_counts = Counter(ip_addresses)

    repeated_ips = {
        ip: count
        for ip, count in ip_counts.items()
        if count > 1
    }

    suspicious_events = []

    if failed_logins >= 3:
        suspicious_events.append({
            "type": "BRUTE_FORCE_INDICATOR",
            "description": (
                f"{failed_logins} failed login attempts detected"
            )
        })

    for ip, count in repeated_ips.items():
        suspicious_events.append({
            "type": "REPEATED_SOURCE_IP",
            "description": (
                f"IP {ip} appeared {count} times"
            )
        })

    return {
        "file_path": str(path),
        "total_lines": len(lines),
        "ip_addresses": sorted(set(ip_addresses)),
        "ip_counts": dict(ip_counts),
        "repeated_ips": repeated_ips,
        "timestamps": sorted(set(timestamps)),
        "usernames": sorted(set(usernames)),
        "ports": sorted(set(ports)),
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "connection_events": connection_events,
        "event_lines": event_lines,
        "suspicious_events": suspicious_events
    }
