from datetime import datetime


def generate_report(
    evidence,
    triage_result=None,
    ioc_result=None,
    timeline_result=None,
    log_result=None,
    risk_result=None,
    incident_summary=None
):
    """
    Generate a structured DFIR investigation report.
    """

    triage_result = triage_result or {}
    ioc_result = ioc_result or {}
    timeline_result = timeline_result or {}
    log_result = log_result or {}
    risk_result = risk_result or {}
    incident_summary = incident_summary or {}

    report = {
        "report_title": "DFIR-X Investigation Report",

        "generated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "case_information": {
            "case_id": evidence["case_id"],
            "evidence_id": evidence["evidence_id"],
            "evidence_name": evidence["evidence_name"],
            "evidence_type": evidence["evidence_type"],
            "source": evidence["source"],
        },

        "evidence_integrity": {
            "original_hash": evidence["original_hash"],
            "current_hash": evidence["current_hash"],
            "integrity_status": evidence["integrity_status"],
        },

        "file_triage": triage_result,

        "ioc_analysis": ioc_result,

        "timeline_analysis": timeline_result,

        "log_analysis": log_result,

        "risk_analysis": risk_result,

        "incident_summary": incident_summary,
    }

    return report
