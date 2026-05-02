import argparse
import json
import re
from datetime import datetime
from pathlib import Path

CONFIG_FILE = Path("config/policy.json")
DATA_FILE = Path("data/credential_requests.json")
REPORT_TXT_FILE = Path("reports/credential_risk_report.txt")
REPORT_JSON_FILE = Path("reports/credential_risk_report.json")
LOG_FILE = Path("logs/credential_events.log")


def load_policy():
    with CONFIG_FILE.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def load_requests():
    with DATA_FILE.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def check_password_strength(password, policy):
    findings = []

    if len(password) < policy["min_length"]:
        findings.append("Password is shorter than required minimum length")

    if policy["require_uppercase"] and not re.search(r"[A-Z]", password):
        findings.append("Missing uppercase character")

    if policy["require_lowercase"] and not re.search(r"[a-z]", password):
        findings.append("Missing lowercase character")

    if policy["require_number"] and not re.search(r"[0-9]", password):
        findings.append("Missing number")

    if policy["require_special"] and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        findings.append("Missing special character")

    return findings


def check_rotation(days_since_rotation, policy):
    if days_since_rotation > policy["max_rotation_days"]:
        return "Rotation overdue"

    return "Rotation compliant"


def calculate_risk_score(strength_findings, rotation_status, role, policy):
    score = 0
    score += len(strength_findings) * 2

    if rotation_status == "Rotation overdue":
        score += 5

    if role.lower() == "admin":
        score += policy["admin_risk_weight"]

    return score


def classify_risk(score):
    if score >= 8:
        return "HIGH"

    if score >= 4:
        return "MEDIUM"

    return "LOW"


def generate_recommendation(risk_level):
    if risk_level == "HIGH":
        return "Immediate credential rotation required. Enforce password policy and review account access."

    if risk_level == "MEDIUM":
        return "Schedule credential rotation and review password complexity requirements."

    return "No immediate action required. Continue monitoring credential health."


def log_event(username, event_type, message, environment):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("a", encoding="utf-8") as log:
        log.write(
            f"{datetime.now().isoformat(timespec='seconds')} | "
            f"{environment.upper()} | {event_type} | {username} | {message}\n"
        )


def analyze_credentials(requests, policy, environment):
    analyzed_results = []

    if LOG_FILE.exists():
        LOG_FILE.unlink()

    for request in requests:
        username = request["username"]
        password = request["requested_password"]
        role = request["role"]
        days_since_rotation = request["days_since_rotation"]

        strength_findings = check_password_strength(password, policy)
        rotation_status = check_rotation(days_since_rotation, policy)
        risk_score = calculate_risk_score(strength_findings, rotation_status, role, policy)
        risk_level = classify_risk(risk_score)
        recommendation = generate_recommendation(risk_level)

        if risk_level == "HIGH":
            log_event(username, "ALERT", "High-risk credential requires immediate review", environment)
        elif risk_level == "MEDIUM":
            log_event(username, "REVIEW", "Credential requires scheduled review", environment)
        else:
            log_event(username, "AUDIT", "Credential passed policy and rotation checks", environment)

        analyzed_results.append(
            {
                "username": username,
                "role": role,
                "days_since_rotation": days_since_rotation,
                "rotation_status": rotation_status,
                "strength_findings": strength_findings,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "recommendation": recommendation
            }
        )

    return analyzed_results


def generate_text_report(results, environment):
    REPORT_TXT_FILE.parent.mkdir(parents=True, exist_ok=True)

    total = len(results)
    high_risk = sum(1 for item in results if item["risk_level"] == "HIGH")
    medium_risk = sum(1 for item in results if item["risk_level"] == "MEDIUM")
    low_risk = sum(1 for item in results if item["risk_level"] == "LOW")

    report_lines = [
        "Cloud Credential Policy And Risk Analysis Report",
        "=" * 55,
        f"Environment: {environment.upper()}",
        f"Total Credentials Reviewed: {total}",
        f"High Risk: {high_risk}",
        f"Medium Risk: {medium_risk}",
        f"Low Risk: {low_risk}",
        ""
    ]

    for item in results:
        report_lines.append(f"User: {item['username']}")
        report_lines.append(f"Role: {item['role']}")
        report_lines.append(f"Rotation Age: {item['days_since_rotation']} days")
        report_lines.append(f"Rotation Status: {item['rotation_status']}")
        report_lines.append(f"Risk Score: {item['risk_score']}")
        report_lines.append(f"Risk Level: {item['risk_level']}")

        if item["strength_findings"]:
            report_lines.append("Password Policy Findings:")
            for finding in item["strength_findings"]:
                report_lines.append(f"- {finding}")
        else:
            report_lines.append("Password Policy Findings: Meets strength requirements")

        report_lines.append("Recommended Action:")
        report_lines.append(f"- {item['recommendation']}")
        report_lines.append("-" * 55)

    REPORT_TXT_FILE.write_text("\n".join(report_lines), encoding="utf-8")


def export_json_report(results, environment):
    REPORT_JSON_FILE.parent.mkdir(parents=True, exist_ok=True)

    output = {
        "environment": environment.upper(),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "results": results
    }

    REPORT_JSON_FILE.write_text(json.dumps(output, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Cloud Credential Policy And Risk Analysis System")
    parser.add_argument("--env", default="dev", help="Environment name, for example dev, test, or prod")
    parser.add_argument("--export-json", action="store_true", help="Export machine-readable JSON report")

    args = parser.parse_args()

    policy = load_policy()
    requests = load_requests()
    results = analyze_credentials(requests, policy, args.env)

    generate_text_report(results, args.env)

    if args.export_json:
        export_json_report(results, args.env)

    print("Cloud Credential Policy And Risk Analysis System")
    print("=" * 55)
    print("Credential risk analysis completed successfully.")
    print(f"Environment: {args.env.upper()}")
    print(f"Text report created: {REPORT_TXT_FILE}")

    if args.export_json:
        print(f"JSON report created: {REPORT_JSON_FILE}")

    print(f"Event log updated: {LOG_FILE}")
    print("")
    print(REPORT_TXT_FILE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
