
#!/usr/bin/env python3
"""
Tether Security Advisory Automation

Modes:
    --preflight
        Verify GitHub token, repository access, admin permission,
        and advisory API read access. Does not create anything.

    --extract INPUT --output OUTPUT
        Extract the machine-readable findings block from Beam output.
        This does not call any external API.

    --submit --input INPUT --output OUTPUT
        Create one private draft repository advisory per eligible finding.

Environment:
    TETHER_ADVISORY_TOKEN
    GITHUB_REPOSITORY       owner/repo
    GITHUB_RUN_URL          optional
    AUDIT_COMMIT_SHA        optional

No third-party Python dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


API_BASE = "https://api.github.com"
API_VERSION = "2026-03-10"

FINDINGS_MARKER = "<!-- TETHER_ADVISORY_FINDINGS_JSON -->"
ADVISORY_MARKER = "<!-- TETHER-AUDIT-FINDING-ID: {finding_id} -->"

VALID_ECOSYSTEMS = {
    "rubygems",
    "npm",
    "pip",
    "maven",
    "nuget",
    "composer",
    "go",
    "rust",
    "erlang",
    "actions",
    "pub",
    "other",
    "swift",
}

VALID_SEVERITIES = {
    "critical",
    "high",
    "medium",
    "low",
}

VALID_CONFIDENCE = {
    "confirmed",
    "high",
    "high confidence",
}

VALID_CVSS_PREFIXES = (
    "CVSS:3.0/",
    "CVSS:3.1/",
    "CVSS:4.0/",
)

MAX_FINDINGS = 100
MAX_TEXT_LENGTH = 100_000


class AuditError(Exception):
    pass


def log(message: str) -> None:
    print(f"[advisories] {message}", flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def require_environment() -> tuple[str, str, str]:
    token = os.environ.get("TETHER_ADVISORY_TOKEN", "").strip()
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()

    if not token:
        raise AuditError("TETHER_ADVISORY_TOKEN is missing.")

    if not repository or "/" not in repository:
        raise AuditError("GITHUB_REPOSITORY must be owner/repo.")

    owner, repo = repository.split("/", 1)

    if not owner or not repo:
        raise AuditError("Invalid GITHUB_REPOSITORY.")

    return token, owner, repo


def api_request(
    method: str,
    path_or_url: str,
    body: dict[str, Any] | None = None,
    *,
    retries: int = 3,
) -> tuple[Any, dict[str, str], int]:
    """
    GET requests may be retried on transient errors.

    POST requests are deliberately NOT retried automatically.
    An uncertain POST is reconciled by looking for its finding marker.
    """

    token, _, _ = require_environment()

    if path_or_url.startswith("https://"):
        url = path_or_url
    else:
        url = API_BASE + path_or_url

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "Tether-Security-Audit",
    }

    data = None

    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")

    attempts = retries if method.upper() == "GET" else 1

    for attempt in range(attempts):
        request = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method=method.upper(),
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=30,
            ) as response:
                raw = response.read().decode("utf-8", errors="replace")
                parsed = json.loads(raw) if raw else None

                response_headers = {
                    key.lower(): value
                    for key, value in response.headers.items()
                }

                return parsed, response_headers, response.status

        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")

            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"message": raw[:1000]}

            response_headers = {
                key.lower(): value
                for key, value in exc.headers.items()
            }

            transient = exc.code in {
                429,
                500,
                502,
                503,
                504,
            }

            if (
                method.upper() == "GET"
                and transient
                and attempt + 1 < attempts
            ):
                retry_after = response_headers.get("retry-after", "")

                try:
                    delay = min(30, max(1, int(retry_after)))
                except ValueError:
                    delay = min(2 ** attempt, 15)

                log(
                    f"GitHub GET returned HTTP {exc.code}; "
                    f"retrying in {delay}s."
                )

                time.sleep(delay)
                continue

            message = parsed.get("message", "Unknown GitHub API error")

            raise AuditError(
                f"GitHub API {method.upper()} {url} returned "
                f"HTTP {exc.code}: {message}"
            ) from exc

        except urllib.error.URLError as exc:
            if (
                method.upper() == "GET"
                and attempt + 1 < attempts
            ):
                delay = min(2 ** attempt, 15)
                log(f"Network error; retrying GET in {delay}s.")
                time.sleep(delay)
                continue

            raise AuditError(
                f"GitHub API connection failed: {exc.reason}"
            ) from exc

        except TimeoutError as exc:
            if (
                method.upper() == "GET"
                and attempt + 1 < attempts
            ):
                time.sleep(min(2 ** attempt, 15))
                continue

            raise AuditError("GitHub API request timed out.") from exc

    raise AuditError("GitHub API request exhausted its retries.")


def preflight() -> None:
    """
    Verify that the token can access the target repository and
    list its security advisories.

    This does not create a test advisory.
    """

    _, owner, repo = require_environment()

    log(f"Checking access to {owner}/{repo}.")

    repository, _, _ = api_request(
        "GET",
        f"/repos/{owner}/{repo}",
    )

    if not isinstance(repository, dict):
        raise AuditError("GitHub returned an invalid repository response.")

    permissions = repository.get("permissions") or {}

    if permissions.get("admin") is not True:
        raise AuditError(
            "The advisory token does not report administrator access "
            "to the target repository. The audit is being stopped "
            "before Beam runs. Verify that the token owner is a "
            "repository administrator or an authorised security manager."
        )

    log("Repository administrator access confirmed.")

    # Listing drafts verifies access to the repository advisory API.
    api_request(
        "GET",
        f"/repos/{owner}/{repo}/security-advisories"
        "?state=draft&per_page=1",
    )

    log("Security Advisory API access confirmed.")
    log("Preflight passed. No advisory was created.")


def clean_text(value: Any, *, required: bool = False) -> str:
    if not isinstance(value, str):
        value = ""

    value = value.strip()

    if len(value) > MAX_TEXT_LENGTH:
        value = value[:MAX_TEXT_LENGTH]

    if required and not value:
        raise AuditError("A required finding field is empty.")

    return value


def extract_json_object(text: str) -> dict[str, Any]:
    """
    Extract the JSON object following the required marker.

    Supports either raw JSON or a fenced JSON block.
    Uses brace balancing so nested objects and arrays are supported.
    """

    marker_position = text.find(FINDINGS_MARKER)

    if marker_position < 0:
        raise AuditError(
            "Beam output does not contain the required findings marker."
        )

    content = text[marker_position + len(FINDINGS_MARKER):].strip()

    # Prefer a fenced JSON block if present.
    fenced = re.search(
        r"```(?:json)?\s*(.*?)```",
        content,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if fenced:
        content = fenced.group(1).strip()

    start = content.find("{")

    if start < 0:
        raise AuditError("No JSON object found after findings marker.")

    depth = 0
    in_string = False
    escaped = False
    end = None

    for index in range(start, len(content)):
        char = content[index]

        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False

            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1

            if depth == 0:
                end = index + 1
                break

    if end is None:
        raise AuditError("JSON object is incomplete.")

    try:
        parsed = json.loads(content[start:end])
    except json.JSONDecodeError as exc:
        raise AuditError(
            f"Invalid findings JSON: {exc}"
        ) from exc

    if not isinstance(parsed, dict):
        raise AuditError("Findings JSON must be an object.")

    if not isinstance(parsed.get("findings"), list):
        raise AuditError("Findings JSON must contain a findings array.")

    return parsed


def extract_mode(input_path: Path, output_path: Path) -> None:
    if not input_path.is_file():
        raise AuditError(f"Beam output does not exist: {input_path}")

    raw = input_path.read_text(encoding="utf-8", errors="replace")

    parsed = extract_json_object(raw)

    findings = parsed["findings"]

    if len(findings) > MAX_FINDINGS:
        raise AuditError(
            f"Beam returned {len(findings)} findings. "
            f"Maximum accepted in one run is {MAX_FINDINGS}."
        )

    result = {
        "schema_version": 1,
        "extracted_at": utc_now(),
        "findings": findings,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    log(f"Extracted {len(findings)} finding(s).")


def validate_finding(
    finding: Any,
    index: int,
) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise AuditError(f"Finding {index} is not an object.")

    finding_id = clean_text(finding.get("finding_id"), required=True)

    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}",
        finding_id,
    ):
        raise AuditError(
            f"Finding {index} has an invalid finding_id."
        )

    title = clean_text(finding.get("title"), required=True)
    summary = clean_text(finding.get("summary"), required=True)
    details = clean_text(finding.get("details"), required=True)
    poc = clean_text(
        finding.get("proof_of_concept") or finding.get("poc"),
        required=True,
    )
    impact = clean_text(finding.get("impact"), required=True)

    if len(title) > 200:
        raise AuditError(f"{finding_id}: title exceeds 200 characters.")

    if len(summary) > 500:
        raise AuditError(f"{finding_id}: summary exceeds 500 characters.")

    severity = clean_text(
        finding.get("severity")
    ).lower()

    if severity not in VALID_SEVERITIES:
        raise AuditError(
            f"{finding_id}: severity must be critical, high, medium or low."
        )

    confidence = clean_text(
        finding.get("confidence")
    ).lower()

    if confidence not in VALID_CONFIDENCE:
        raise AuditError(
            f"{finding_id}: confidence is not confirmed/high."
        )

    if finding.get("eligible_for_advisory") is not True:
        raise AuditError(
            f"{finding_id}: finding is not marked eligible_for_advisory=true."
        )

    vector = clean_text(
        finding.get("cvss_vector_string")
    )

    if vector:
        if not vector.startswith(VALID_CVSS_PREFIXES):
            raise AuditError(
                f"{finding_id}: unsupported or malformed CVSS vector prefix."
            )

        if not re.fullmatch(
            r"CVSS:(?:3\.0|3\.1|4\.0)/[A-Za-z0-9:/._-]+",
            vector,
        ):
            raise AuditError(
                f"{finding_id}: malformed CVSS vector."
            )

    raw_cwes = finding.get("cwe_ids") or []

    if not isinstance(raw_cwes, list):
        raise AuditError(f"{finding_id}: cwe_ids must be an array.")

    cwe_ids = []

    for cwe in raw_cwes:
        cwe = clean_text(cwe).upper()

        if re.fullmatch(r"CWE-\d+", cwe):
            cwe_ids.append(cwe)

    cwe_ids = sorted(set(cwe_ids))[:20]

    raw_products = finding.get("affected_products") or []

    if not isinstance(raw_products, list):
        raise AuditError(
            f"{finding_id}: affected_products must be an array."
        )

    products = []

    for product in raw_products[:20]:
        if not isinstance(product, dict):
            continue

        ecosystem = clean_text(
            product.get("ecosystem")
        ).lower()

        if ecosystem not in VALID_ECOSYSTEMS:
            continue

        package_name = clean_text(product.get("name")) or None

        vulnerable_range = clean_text(
            product.get("vulnerable_version_range")
        ) or None

        patched_versions = clean_text(
            product.get("patched_versions")
        ) or None

        functions = product.get("vulnerable_functions") or []

        if not isinstance(functions, list):
            functions = []

        functions = [
            clean_text(item)
            for item in functions
            if clean_text(item)
        ][:30]

        products.append({
            "package": {
                "ecosystem": ecosystem,
                "name": package_name,
            },
            "vulnerable_version_range": vulnerable_range,
            "patched_versions": patched_versions,
            "vulnerable_functions": functions or None,
        })

    # Native Tether application vulnerabilities may not belong to
    # a package-manager ecosystem. GitHub requires a product entry.
    if not products:
        products = [{
            "package": {
                "ecosystem": "other",
                "name": "Tether",
            },
            "vulnerable_version_range": None,
            "patched_versions": None,
            "vulnerable_functions": None,
        }]

    return {
        "finding_id": finding_id,
        "title": title,
        "summary": summary,
        "details": details,
        "proof_of_concept": poc,
        "impact": impact,
        "severity": severity,
        "cvss_vector_string": vector or None,
        "cwe_ids": cwe_ids,
        "products": products,
    }


def list_all_advisories() -> list[dict[str, Any]]:
    _, owner, repo = require_environment()

    url = (
        f"{API_BASE}/repos/{owner}/{repo}/security-advisories"
        "?per_page=100"
    )

    advisories = []

    while url:
        page, headers, _ = api_request("GET", url)

        if not isinstance(page, list):
            raise AuditError(
                "GitHub returned an invalid advisory listing."
            )

        advisories.extend(
            item for item in page if isinstance(item, dict)
        )

        link_header = headers.get("link", "")
        next_url = None

        for part in link_header.split(","):
            if 'rel="next"' in part:
                match = re.search(r"<([^>]+)>", part)

                if match:
                    next_url = match.group(1)

        url = next_url

    return advisories


def existing_finding_ids(
    advisories: list[dict[str, Any]],
) -> set[str]:
    known = set()

    pattern = re.compile(
        r"<!-- TETHER-AUDIT-FINDING-ID: "
        r"([A-Za-z0-9][A-Za-z0-9._-]{2,63}) -->"
    )

    for advisory in advisories:
        description = advisory.get("description") or ""

        for match in pattern.finditer(description):
            known.add(match.group(1))

    return known


def build_description(
    finding: dict[str, Any],
) -> str:
    marker = ADVISORY_MARKER.format(
        finding_id=finding["finding_id"]
    )

    run_url = os.environ.get("GITHUB_RUN_URL", "").strip()
    commit_sha = os.environ.get("AUDIT_COMMIT_SHA", "").strip()

    metadata = [
        marker,
        "",
        "## Summary",
        finding["summary"],
        "",
        "## Details",
        finding["details"],
        "",
        "## Proof of Concept",
        finding["proof_of_concept"],
        "",
        "## Impact",
        finding["impact"],
        "",
        "---",
        "",
        "## Automated Audit Metadata",
        f"- Finding ID: `{finding['finding_id']}`",
        f"- Audit commit: `{commit_sha or 'Not provided'}`",
        f"- Generated: `{utc_now()}`",
    ]

    if run_url:
        metadata.append(f"- Workflow run: {run_url}")

    metadata.extend([
        "",
        "This advisory was created automatically as a private draft. "
        "The finding should be independently reviewed before publication.",
    ])

    return "\n".join(metadata)


def build_payload(
    finding: dict[str, Any],
) -> dict[str, Any]:
    payload = {
        "summary": finding["title"],
        "description": build_description(finding),
        "vulnerabilities": finding["products"],
        "start_private_fork": False,
    }

    if finding["cwe_ids"]:
        payload["cwe_ids"] = finding["cwe_ids"]

    # GitHub requires either severity OR cvss_vector_string, not both.
    if finding["cvss_vector_string"]:
        payload["cvss_vector_string"] = (
            finding["cvss_vector_string"]
        )
    else:
        payload["severity"] = finding["severity"]

    return payload


def find_advisory_by_marker(
    finding_id: str,
) -> dict[str, Any] | None:
    advisories = list_all_advisories()
    marker = ADVISORY_MARKER.format(finding_id=finding_id)

    for advisory in advisories:
        if marker in (advisory.get("description") or ""):
            return advisory

    return None


def submit_mode(
    input_path: Path,
    output_path: Path,
) -> None:
    _, owner, repo = require_environment()

    if not input_path.is_file():
        raise AuditError(f"Findings input not found: {input_path}")

    data = json.loads(input_path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise AuditError("Findings input must be a JSON object.")

    raw_findings = data.get("findings")

    if not isinstance(raw_findings, list):
        raise AuditError("Findings input has no findings array.")

    if len(raw_findings) > MAX_FINDINGS:
        raise AuditError("Too many findings in one submission.")

    log(f"Loading existing advisories from {owner}/{repo}.")

    advisories = list_all_advisories()
    existing_ids = existing_finding_ids(advisories)

    results = {
        "repository": f"{owner}/{repo}",
        "created": [],
        "skipped": [],
        "failed": [],
        "started_at": utc_now(),
    }

    seen_this_run = set()

    for index, raw_finding in enumerate(raw_findings, start=1):
        finding_id = None

        try:
            finding_id = clean_text(
                raw_finding.get("finding_id")
                if isinstance(raw_finding, dict)
                else ""
            )

            finding = validate_finding(raw_finding, index)
            finding_id = finding["finding_id"]

            if finding_id in seen_this_run:
                results["skipped"].append({
                    "finding_id": finding_id,
                    "reason": "Duplicate finding ID within this audit.",
                })
                continue

            seen_this_run.add(finding_id)

            if finding_id in existing_ids:
                log(f"Skipping {finding_id}: advisory already exists.")

                results["skipped"].append({
                    "finding_id": finding_id,
                    "reason": "An advisory with this finding ID already exists.",
                })
                continue

            log(
                f"Creating draft advisory for {finding_id} "
                f"({finding['severity']})."
            )

            payload = build_payload(finding)

            try:
                created, _, status = api_request(
                    "POST",
                    f"/repos/{owner}/{repo}/security-advisories",
                    payload,
                )

                if status != 201 or not isinstance(created, dict):
                    raise AuditError(
                        "GitHub did not return a valid created advisory."
                    )

                results["created"].append({
                    "finding_id": finding_id,
                    "ghsa_id": created.get("ghsa_id"),
                    "html_url": created.get("html_url"),
                    "state": created.get("state", "draft"),
                })

                existing_ids.add(finding_id)

                log(
                    f"Created {finding_id}: "
                    f"{created.get('ghsa_id', 'GHSA ID unavailable')}."
                )

            except Exception as post_error:
                # A network timeout after a successful POST is ambiguous.
                # Reconcile by checking whether GitHub created the marker.
                log(
                    f"Submission outcome uncertain for {finding_id}; "
                    "checking GitHub before reporting failure."
                )

                try:
                    recovered = find_advisory_by_marker(finding_id)

                    if recovered:
                        results["created"].append({
                            "finding_id": finding_id,
                            "ghsa_id": recovered.get("ghsa_id"),
                            "html_url": recovered.get("html_url"),
                            "state": recovered.get("state", "draft"),
                            "recovered_after_uncertain_response": True,
                        })

                        existing_ids.add(finding_id)
                        log(f"Recovered existing advisory for {finding_id}.")
                        continue

                except Exception as reconcile_error:
                    log(
                        f"Could not reconcile {finding_id}: "
                        f"{reconcile_error}"
                    )

                raise post_error

        except Exception as exc:
            log(f"Finding failed: {finding_id or index}: {exc}")

            results["failed"].append({
                "finding_id": finding_id or f"index-{index}",
                "error": str(exc),
            })

    results["finished_at"] = utc_now()

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    log(
        f"Finished: {len(results['created'])} created, "
        f"{len(results['skipped'])} skipped, "
        f"{len(results['failed'])} failed."
    )

    if results["failed"]:
        raise AuditError(
            f"{len(results['failed'])} advisory submission(s) failed. "
            "See the JSON results."
        )


def main() -> int:
    parser = argparse.ArgumentParser()

    mode = parser.add_mutually_exclusive_group(required=True)

    mode.add_argument(
        "--preflight",
        action="store_true",
    )

    mode.add_argument(
        "--extract",
        metavar="INPUT",
    )

    mode.add_argument(
        "--submit",
        action="store_true",
    )

    parser.add_argument(
        "--input",
        help="Structured findings JSON for --submit.",
    )

    parser.add_argument(
        "--output",
        help="Output JSON path.",
    )

    args = parser.parse_args()

    try:
        if args.preflight:
            preflight()
            return 0

        if not args.output:
            raise AuditError("--output is required.")

        output_path = Path(args.output)

        if args.extract:
            extract_mode(Path(args.extract), output_path)
            return 0

        if args.submit:
            if not args.input:
                raise AuditError("--input is required with --submit.")

            submit_mode(Path(args.input), output_path)
            return 0

    except Exception as exc:
        log(f"ERROR: {exc}")
        return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
