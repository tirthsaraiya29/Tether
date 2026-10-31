
import os
import sys
import json
import ssl
import smtplib
import hashlib
import subprocess
import urllib.request
import urllib.error
import html

from pathlib import Path
from email.message import EmailMessage
from datetime import datetime, timezone
from urllib.parse import quote


ROOT = Path.cwd()

OLLAMA_URL = "https://ollama.com/api/chat"
OLLAMA_MODEL = "gpt-oss:120b"

RECIPIENT = "tirthsaraiya29@gmail.com"
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

MAX_REPORT_CHARS = 300_000


def require_secrets():
    required = [
        "OLLAMA_SUMMARY_API_KEY",
        "SMTP_USERNAME",
        "SMTP_APP_PASSWORD",
    ]

    missing = [name for name in required if not os.getenv(name)]

    if missing:
        raise RuntimeError(
            "Missing GitHub Actions secrets: " + ", ".join(missing)
        )

    if os.environ["SMTP_USERNAME"].lower() != RECIPIENT.lower():
        raise RuntimeError(
            "SMTP_USERNAME must equal the configured recipient."
        )


def ollama_request(prompt, report=None):
    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior application security engineer. "
                    "Produce accurate, technically useful security "
                    "report summaries. Never invent findings, claim "
                    "a vulnerability is fixed without evidence, or "
                    "treat an incomplete audit as a clean audit."
                ),
            },
            {
                "role": "user",
                "content": prompt + (
                    "\n\nREPORT CONTENT:\n" + report
                    if report is not None else ""
                ),
            },
        ],
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": (
                "Bearer " + os.environ["OLLAMA_SUMMARY_API_KEY"]
            ),
            "Content-Type": "application/json",
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=180) as response:
        result = json.loads(response.read().decode("utf-8"))

    content = result.get("message", {}).get("content")

    if not content:
        raise RuntimeError("Ollama returned an empty response.")

    return content


def test_smtp():
    context = ssl.create_default_context()

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()

        server.login(
            os.environ["SMTP_USERNAME"],
            os.environ["SMTP_APP_PASSWORD"],
        )


def preflight():
    print("Checking Ollama authentication and model inference...")

    result = ollama_request(
        "Reply with exactly: OLLAMA_PREFLIGHT_OK"
    )

    if "OLLAMA_PREFLIGHT_OK" not in result:
        raise RuntimeError("Ollama preflight returned unexpected output.")

    print("Ollama authentication and inference: OK")

    print("Checking Gmail SMTP TLS and authentication...")
    test_smtp()
    print("Gmail SMTP authentication: OK")

    print("Preflight successful. No email was sent.")


def get_added_reports():
    before = os.environ.get("BEFORE_SHA")
    after = os.environ.get("AFTER_SHA")

    if not before or before == "0000000000000000000000000000000000000000":
        result = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", after],
            capture_output=True,
            text=True,
            check=True,
        )

        paths = result.stdout.splitlines()

    else:
        result = subprocess.run(
            [
                "git", "diff",
                "--diff-filter=A",
                "--name-only",
                before,
                after,
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        paths = result.stdout.splitlines()

    return [
        path for path in paths
        if path.startswith("runs/") and path.endswith(".md")
    ]


def get_latest_report():
    reports = list((ROOT / "runs").rglob("*.md"))

    if not reports:
        raise RuntimeError("No Markdown reports found in runs/.")

    return str(
        max(reports, key=lambda path: path.stat().st_mtime)
        .relative_to(ROOT)
    )


def validate_report_path(path):
    if not path:
        raise RuntimeError("No report path supplied.")

    candidate = Path(path)

    if candidate.is_absolute() or ".." in candidate.parts:
        raise RuntimeError("Invalid report path.")

    if not path.startswith("runs/") or candidate.suffix.lower() != ".md":
        raise RuntimeError("Reports must be Markdown files inside runs/.")

    resolved = (ROOT / candidate).resolve()

    if not resolved.is_relative_to((ROOT / "runs").resolve()):
        raise RuntimeError("Report path escapes runs/.")

    if not resolved.is_file():
        raise RuntimeError("Report does not exist: " + path)

    return resolved


def marker_path(report_path, content):
    digest = hashlib.sha256(
        (report_path + "\0" + hashlib.sha256(content).hexdigest())
        .encode("utf-8")
    ).hexdigest()

    return ROOT / ".notifications" / (digest + ".sent")


def summarize_report(report):
    prompt = """
Prepare a medium-depth engineering briefing for a software security audit.

Return valid JSON only, with this exact structure:

{
  "subject": "Concise email subject",
  "overview": "Executive technical overview",
  "audit_status": "completed, incomplete, or failed",
  "severity_breakdown": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "informational": 0
  },
  "key_findings": [
    {
      "title": "Finding title",
      "severity": "Severity",
      "explanation": "Technical explanation",
      "impact": "Practical security impact"
    }
  ],
  "historical_comparison": "Comparison with earlier reports if available",
  "recommended_actions": [
    "Specific recommended action"
  ],
  "limitations": "Missing evidence, incomplete checks, or limitations"
}

Rules:
- Preserve the actual findings and their severity.
- Do not invent vulnerability counts.
- Do not claim a clean audit if the audit failed or was incomplete.
- Mention important unpatched findings.
- Distinguish confirmed vulnerabilities from suspected issues.
- Identify regressions or newly introduced issues if the report supports them.
- Do not reproduce secrets, credentials, tokens, or lengthy exploit payloads.
- Keep the summary concise but technically meaningful.
- If historical data is unavailable, explicitly say so.
"""

    raw = ollama_request(prompt, report)

    # Extract JSON if the model wraps it in Markdown fences.
    raw = raw.strip()

    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1]
        raw = raw.rsplit("```", 1)[0].strip()

    result = json.loads(raw)

    required = [
        "subject",
        "overview",
        "audit_status",
        "severity_breakdown",
        "key_findings",
        "historical_comparison",
        "recommended_actions",
        "limitations",
    ]

    for field in required:
        if field not in result:
            raise RuntimeError("Summary missing field: " + field)

    if result["audit_status"] not in [
        "completed", "incomplete", "failed"
    ]:
        raise RuntimeError("Invalid audit status in AI summary.")

    return result


def send_email(summary, report_path):
    report_url = (
        os.environ["GITHUB_SERVER_URL"]
        + "/"
        + os.environ["GITHUB_REPOSITORY"]
        + "/blob/"
        + quote(os.environ["BRANCH_NAME"], safe="")
        + "/"
        + quote(report_path, safe="/")
    )

    status = summary["audit_status"].upper()

    subject = "[Tether Security Audit] " + summary["subject"]

    if status != "COMPLETED":
        subject = "[ACTION REQUIRED - " + status + "] " + subject

    message = EmailMessage()
    message["From"] = RECIPIENT
    message["To"] = RECIPIENT
    message["Subject"] = subject

    breakdown = summary["severity_breakdown"]

    lines = [
        "TETHER SECURITY AUDIT BRIEFING",
        "=" * 36,
        "",
        "Audit status: " + status,
        "",
        "OVERVIEW",
        summary["overview"],
        "",
        "SEVERITY BREAKDOWN",
    ]

    for severity, count in breakdown.items():
        lines.append(f"{severity.capitalize()}: {count}")

    lines.extend(["", "KEY FINDINGS"])

    for index, finding in enumerate(summary["key_findings"], 1):
        lines.extend([
            "",
            f"{index}. {finding['title']}",
            "Severity: " + finding["severity"],
            finding["explanation"],
            "Impact: " + finding["impact"],
        ])

    lines.extend([
        "",
        "HISTORICAL COMPARISON",
        summary["historical_comparison"],
        "",
        "RECOMMENDED ACTIONS",
    ])

    for action in summary["recommended_actions"]:
        lines.append("- " + action)

    lines.extend([
        "",
        "LIMITATIONS",
        summary["limitations"],
        "",
        "FULL REPORT",
        report_url,
        "",
        "Automated summary generated by Ollama gpt-oss:120b.",
        "Refer to the original report for complete evidence.",
    ])

    message.set_content("\n".join(lines))

    # Escape model-generated text before rendering HTML.
    safe_lines = "<br>".join(
        html.escape(line) for line in lines
    )

    message.add_alternative(
        "<html><body><p>" + safe_lines + "</p></body></html>",
        subtype="html",
    )

    context = ssl.create_default_context()

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()

        server.login(
            os.environ["SMTP_USERNAME"],
            os.environ["SMTP_APP_PASSWORD"],
        )

        server.send_message(message)

    print("Email sent to " + RECIPIENT)


def main():
    mode = os.getenv("MODE", "summarize_latest")
    event = os.getenv("EVENT_NAME", "")

    # A push that only modifies an existing report must not
    # trigger a notification.
    if event == "push":
        reports = get_added_reports()

        if not reports:
            print("No newly added Markdown reports. Nothing to do.")
            return

    else:
        reports = []

    require_secrets()

    if mode == "preflight":
        preflight()
        return

    if event == "workflow_dispatch":
        requested = os.getenv("REPORT_PATH", "").strip()

        if requested:
            reports = [requested]
        else:
            reports = [get_latest_report()]

    if not reports:
        raise RuntimeError("No reports selected.")

    resend = os.getenv("RESEND", "").lower() == "true"

    for report_path in reports:
        report_file = validate_report_path(report_path)
        content = report_file.read_bytes()

        if len(content) > MAX_REPORT_CHARS:
            raise RuntimeError(
                f"{report_path} is too large for safe summarisation."
            )

        marker = marker_path(report_path, content)

        if marker.exists() and not resend:
            print("Already emailed; skipping: " + report_path)
            continue

        print("Summarising: " + report_path)

        report_text = content.decode("utf-8")
        summary = summarize_report(report_text)

        send_email(summary, report_path)

        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            datetime.now(timezone.utc).isoformat() + "\n",
            encoding="utf-8",
        )

        print("Notification recorded: " + report_path)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("ERROR:", str(error), file=sys.stderr)
        sys.exit(1)
