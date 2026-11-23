from flask import Flask, render_template, request, redirect, url_for
from modules.database import initialize_database, get_connection
from modules.hashing import calculate_sha256, verify_sha256
from modules.file_triage import analyze_file
from modules.incident_summary import generate_incident_summary
from modules.ioc_extractor import extract_iocs
from modules.timeline import generate_timeline
from modules.log_analyzer import analyze_log
from modules.risk_analyzer import calculate_risk
from modules.report_generator import generate_report
import os

app = Flask(__name__)

initialize_database()


@app.route("/")
def dashboard():
    connection = get_connection()

    cases = connection.execute(
        "SELECT * FROM cases ORDER BY id DESC"
    ).fetchall()

    evidence_records = connection.execute(
        "SELECT * FROM evidence ORDER BY id DESC"
    ).fetchall()

    evidence_count = len(evidence_records)

    verified_count = sum(
        1 for evidence in evidence_records
        if evidence["integrity_status"] == "Verified"
    )

    mismatch_count = sum(
        1 for evidence in evidence_records
        if evidence["integrity_status"] == "Mismatch"
    )

    risk_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for evidence in evidence_records:

        file_path = evidence["file_path"]

        if file_path and os.path.isfile(file_path):

            try:

                log_result = analyze_log(file_path)

                risk_result = calculate_risk(
                    log_result=log_result,
                    integrity_status=evidence["integrity_status"]
                )

                risk_level = risk_result.get(
                    "risk_level",
                    "LOW"
                )

                if risk_level in risk_counts:
                    risk_counts[risk_level] += 1

            except (OSError, PermissionError, FileNotFoundError):
                pass

    recent_evidence = evidence_records[:5]


    latest_evidence_id = (
        evidence_records[0]["id"]
        if evidence_records
        else None
    )

    connection.close()

    return render_template(
        "dashboard.html",
        cases=cases,
        evidence_count=evidence_count,
        verified_count=verified_count,
        mismatch_count=mismatch_count,
        recent_evidence=recent_evidence,
        risk_counts=risk_counts,
	latest_evidence_id=latest_evidence_id
    )


@app.route("/create-case", methods=["GET", "POST"])
def create_case():

    if request.method == "POST":

        case_id = request.form["case_id"]
        case_name = request.form["case_name"]
        investigator = request.form["investigator"]
        severity = request.form["severity"]
        description = request.form["description"]

        connection = get_connection()

        connection.execute("""
            INSERT INTO cases
            (case_id, case_name, investigator, severity, description)
            VALUES (?, ?, ?, ?, ?)
        """, (
            case_id,
            case_name,
            investigator,
            severity,
            description
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("dashboard"))

    return render_template("create_case.html")


@app.route("/add-evidence", methods=["GET", "POST"])
def add_evidence():

    if request.method == "POST":

        evidence_id = request.form["evidence_id"]
        case_id = request.form["case_id"]
        evidence_name = request.form["evidence_name"]
        evidence_type = request.form["evidence_type"]
        source = request.form["source"]
        file_path = request.form["file_path"]
        description = request.form["description"]

        # Check whether file exists
        if not os.path.isfile(file_path):
            return "Error: Evidence file does not exist."

        # Automatically calculate SHA-256
        original_hash = calculate_sha256(file_path)

        connection = get_connection()

        connection.execute("""
            INSERT INTO evidence
            (
                evidence_id,
                case_id,
                evidence_name,
                evidence_type,
                source,
                original_hash,
                current_hash,
                integrity_status,
                description,
                file_path
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            evidence_id,
            case_id,
            evidence_name,
            evidence_type,
            source,
            original_hash,
            original_hash,
            "Verified",
            description,
            file_path
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("evidence_list"))

    return render_template("add_evidence.html")


@app.route("/evidence")
def evidence_list():

    connection = get_connection()

    evidence = connection.execute("""
        SELECT * FROM evidence
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "evidence.html",
        evidence=evidence
    )


@app.route("/verify-evidence/<int:evidence_id>")
def verify_evidence(evidence_id):

    connection = get_connection()

    evidence = connection.execute("""
        SELECT * FROM evidence
        WHERE id = ?
    """, (evidence_id,)).fetchone()

    if evidence is None:
        connection.close()
        return "Evidence not found."

    file_path = evidence["file_path"]

    if not file_path or not os.path.isfile(file_path):
        connection.execute("""
            UPDATE evidence
            SET integrity_status = ?,
                current_hash = ?
            WHERE id = ?
        """, (
            "Evidence File Missing",
            None,
            evidence_id
        ))

        connection.commit()
        connection.close()

        return redirect(url_for("evidence_list"))

    is_valid, current_hash = verify_sha256(
        file_path,
        evidence["original_hash"]
    )

    if is_valid:
        status = "Verified"
    else:
        status = "Integrity Violation"

    connection.execute("""
        UPDATE evidence
        SET current_hash = ?,
            integrity_status = ?
        WHERE id = ?
    """, (
        current_hash,
        status,
        evidence_id
    ))

    connection.commit()
    connection.close()

    return redirect(url_for("evidence_list"))
@app.route("/analyze/<int:evidence_id>")
def analyze_evidence(evidence_id):
    connection = get_connection()

    evidence = connection.execute("""
        SELECT * FROM evidence
        WHERE id = ?
    """, (evidence_id,)).fetchone()

    connection.close()

    if evidence is None:
        return "Evidence record not found.", 404

    file_path = evidence["file_path"]

    if not file_path or not os.path.isfile(file_path):
        return render_template(
            "evidence_analysis.html",
            evidence=evidence,
            result=None,
            error="Evidence file is missing. Check its saved path."
        )

    try:
        result = analyze_file(
            file_path,
            evidence["original_hash"]
        )
    except (OSError, PermissionError, FileNotFoundError) as error:
        return render_template(
            "evidence_analysis.html",
            evidence=evidence,
            result=None,
            error=f"Could not analyze this file: {error}"
        )

    return render_template(
        "evidence_analysis.html",
        evidence=evidence,
        result=result,
        error=None
    )
@app.route("/ioc/<int:evidence_id>")
def ioc_analysis(evidence_id):

    connection = get_connection()

    evidence = connection.execute("""
        SELECT * FROM evidence
        WHERE id = ?
    """, (evidence_id,)).fetchone()

    connection.close()

    if evidence is None:
        return "Evidence record not found.", 404

    file_path = evidence["file_path"]

    if not file_path or not os.path.isfile(file_path):
        return render_template(
            "ioc_analysis.html",
            evidence=evidence,
            result=None,
            error="Evidence file is missing. Check its saved path."
        )

    try:
        result = extract_iocs(file_path)

    except (OSError, PermissionError, FileNotFoundError) as error:
        return render_template(
            "ioc_analysis.html",
            evidence=evidence,
            result=None,
            error=f"Could not extract IOCs: {error}"
        )

    return render_template(
        "ioc_analysis.html",
        evidence=evidence,
        result=result,
        error=None
    )
@app.route("/timeline/<int:evidence_id>")
def timeline_analysis(evidence_id):

    connection = get_connection()

    evidence = connection.execute("""
        SELECT * FROM evidence
        WHERE id = ?
    """, (evidence_id,)).fetchone()

    connection.close()

    if evidence is None:
        return "Evidence record not found.", 404

    file_path = evidence["file_path"]

    if not file_path or not os.path.isfile(file_path):
        return render_template(
            "timeline.html",
            evidence=evidence,
            result=None,
            error="Evidence file is missing. Check its saved path."
        )

    try:
        result = generate_timeline(file_path)

    except (OSError, PermissionError, FileNotFoundError, ValueError) as error:
        return render_template(
            "timeline.html",
            evidence=evidence,
            result=None,
            error=f"Could not generate timeline: {error}"
        )

    return render_template(
        "timeline.html",
        evidence=evidence,
        result=result,
        error=None
    )
@app.route("/log-analysis/<int:evidence_id>")
def log_analysis(evidence_id):

    connection = get_connection()

    evidence = connection.execute("""
        SELECT * FROM evidence
        WHERE id = ?
    """, (evidence_id,)).fetchone()

    connection.close()

    if evidence is None:
        return "Evidence record not found.", 404

    file_path = evidence["file_path"]

    if not file_path or not os.path.isfile(file_path):
        return "Evidence file is missing.", 404

    try:
        result = analyze_log(file_path)

    except (OSError, PermissionError, FileNotFoundError) as error:
        return f"Could not analyze log: {error}", 500

    return render_template(
        "log_analysis.html",
        evidence=evidence,
        result=result
    )
@app.route("/risk-analysis/<int:evidence_id>")
def risk_analysis(evidence_id):

    connection = get_connection()

    evidence = connection.execute("""
        SELECT * FROM evidence
        WHERE id = ?
    """, (evidence_id,)).fetchone()

    connection.close()

    if evidence is None:
        return "Evidence record not found.", 404

    file_path = evidence["file_path"]

    if not file_path or not os.path.isfile(file_path):
        return "Evidence file is missing.", 404

    try:
        log_result = analyze_log(file_path)

        risk_result = calculate_risk(
            log_result=log_result,
            integrity_status=evidence["integrity_status"]
        )

    except (OSError, PermissionError, FileNotFoundError) as error:
        return f"Could not calculate risk: {error}", 500

    return render_template(
        "risk_analysis.html",
        evidence=evidence,
        result=risk_result
    )
@app.route("/incident-summary/<int:evidence_id>")
def incident_summary(evidence_id):

    connection = get_connection()

    evidence = connection.execute("""
        SELECT * FROM evidence
        WHERE id = ?
    """, (evidence_id,)).fetchone()

    connection.close()

    if evidence is None:
        return "Evidence record not found.", 404

    # Basic incident summary
    summary = generate_incident_summary(
        dict(evidence),
        iocs={},
        timeline={}
    )

    return render_template(
        "incident_summary.html",
        evidence=evidence,
        summary=summary
    )
@app.route("/report/<int:evidence_id>")
def investigation_report(evidence_id):

    connection = get_connection()

    evidence = connection.execute("""
        SELECT * FROM evidence
        WHERE id = ?
    """, (evidence_id,)).fetchone()

    connection.close()

    if evidence is None:
        return "Evidence record not found.", 404

    file_path = evidence["file_path"]

    if not file_path or not os.path.isfile(file_path):
        return "Evidence file is missing.", 404

    try:

        triage_result = analyze_file(
            file_path,
            evidence["original_hash"]
        )

        ioc_result = extract_iocs(file_path)

        timeline_result = generate_timeline(file_path)

        log_result = analyze_log(file_path)

        risk_result = calculate_risk(
            log_result=log_result,
            integrity_status=evidence["integrity_status"]
        )

        incident_summary = generate_incident_summary(
            dict(evidence),
            iocs=ioc_result,
            timeline=timeline_result,
	    risk_result=risk_result
        )

        report = generate_report(
            evidence=evidence,
            triage_result=triage_result,
            ioc_result=ioc_result,
            timeline_result=timeline_result,
            log_result=log_result,
            risk_result=risk_result,
            incident_summary=incident_summary
        )

    except (OSError, PermissionError, FileNotFoundError) as error:
        return f"Could not generate investigation report: {error}", 500

    return render_template(
        "investigation_report.html",
        evidence=evidence,
        report=report
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
