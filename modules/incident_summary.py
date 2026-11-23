from datetime import datetime


def generate_incident_summary(
    evidence,
    iocs=None,
    timeline=None,
    risk_result=None
):
    """
    Generate a descriptive incident summary.

    Risk scoring is handled by risk_analyzer.py.
    This module summarizes the investigation findings
    without creating a second risk score.
    """

    iocs = iocs or {}
    timeline = timeline or {}
    risk_result = risk_result or {}

    # IOC counts
    ip_count = len(iocs.get("ip_addresses", []))
    url_count = len(iocs.get("urls", []))
    email_count = len(iocs.get("email_addresses", []))
    domain_count = len(iocs.get("domains", []))
    hash_count = len(iocs.get("hashes", []))

    # Evidence integrity
    original_hash = evidence.get("original_hash")
    current_hash = evidence.get("current_hash")

    integrity_status = evidence.get(
        "integrity_status",
        "Unknown"
    )

    # Build findings
    findings = []

    if ip_count > 0:
        findings.append(
            f"{ip_count} IP address IOC(s) detected"
        )

    if url_count > 0:
        findings.append(
            f"{url_count} URL IOC(s) detected"
        )

    if email_count > 0:
        findings.append(
            f"{email_count} email address IOC(s) detected"
        )

    if domain_count > 0:
        findings.append(
            f"{domain_count} domain IOC(s) detected"
        )

    if hash_count > 0:
        findings.append(
            f"{hash_count} hash IOC(s) detected"
        )

    if (
        original_hash
        and current_hash
        and original_hash != current_hash
    ):
        findings.append(
            "Evidence integrity mismatch detected"
        )

    if not findings:
        findings.append(
            "No significant IOC or integrity findings detected"
        )

    # Main risk information comes from risk_analyzer.py
    risk_score = risk_result.get("risk_score", 0)
    risk_level = risk_result.get(
        "risk_level",
        "UNKNOWN"
    )

    return {
        "summary": (
            f"Investigation completed for "
            f"{evidence.get('evidence_name', 'evidence')}. "
            f"The automated assessment produced a "
            f"{risk_level} risk level with a score of "
            f"{risk_score}."
        ),

        "risk_score": risk_score,

        "risk_level": risk_level,

        "findings": findings,

        "ioc_counts": {
            "ips": ip_count,
            "urls": url_count,
            "emails": email_count,
            "domains": domain_count,
            "hashes": hash_count
        },

        "integrity_status": integrity_status,

        "generated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }
