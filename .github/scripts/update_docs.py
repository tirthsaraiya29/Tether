import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

API_URL = "https://ollama.com/api/chat"
GITHUB_API_URL = "https://api.github.com"

ROOT = Path.cwd()
DOCS = {
    "README.md": ROOT / "README.md",
    "index.html": ROOT / "index.html",
}

IGNORED_EXACT = {
    "README.md",
    "index.html",
    ".github/workflows/ai-documentation.yml",
    ".github/scripts/update_docs.py",
}

IGNORED_EXTENSIONS = {
    ".lock",
    ".sln",
    ".vcxproj",
    ".vcxproj.filters",
    ".csproj",
    ".jar",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".ico",
    ".bin",
    ".exe",
    ".dll",
    ".pdb",
}

IGNORED_DIR_PREFIXES = (
    ".git/",
    ".github/",
    ".gradle/",
    "gradle/",
    "build/",
    "bin/",
    "obj/",
    ".idea/",
    ".vs/",
)

MAX_DIFF_CHARS = 160_000
MAX_SOURCE_FILE_CHARS = 20_000
MAX_SOURCE_CONTEXT_CHARS = 80_000
MAX_DOCUMENT_CHARS = 1_000_000

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r".*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

TOKEN_RE = re.compile(
    r"\b(?:"
    r"gh[pousr]_[A-Za-z0-9_]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|sk-[A-Za-z0-9_-]{20,}"
    r")\b"
)

SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?im)^([ \t]*["']?
    (?:api[_-]?key|access[_-]?token|password|client[_-]?secret)
    ["']?[ \t]*[:=][ \t]*)
    (["']?)[^\r\n]+""",
    re.VERBOSE,
)


def run_git(*args):
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout


def redact(text):
    text = PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = TOKEN_RE.sub("[REDACTED TOKEN]", text)
    return SECRET_ASSIGNMENT_RE.sub(
        lambda match: match.group(1) + "[REDACTED]",
        text,
    )


def set_output(name, value):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return

    with open(output_file, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def write_summary(lines):
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    with open(summary_file, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def format_numbered_lines(text):
    """Add 1-based line prefixes so the LLM can reference exact line numbers."""
    lines = text.splitlines()
    return "\n".join(f"{idx + 1:5d} | {line}" for idx, line in enumerate(lines))


def find_last_successful_commit():
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    branch = os.environ.get("BRANCH_NAME", "").strip()
    workflow_file = "ai-documentation.yml"

    if not token or not repo or not branch:
        return ""

    url = (
        f"{GITHUB_API_URL}/repos/{repo}/actions/workflows/{workflow_file}/runs"
        f"?branch={branch}&status=completed&conclusion=success&per_page=1"
    )

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Tether-CI-Documentation",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            data = json.loads(res.read().decode("utf-8"))
            runs = data.get("workflow_runs", [])
            if runs:
                sha = runs[0].get("head_sha", "").strip()
                if sha:
                    try:
                        run_git("cat-file", "-e", f"{sha}^{{commit}}")
                        return sha
                    except subprocess.CalledProcessError:
                        pass
    except Exception as exc:
        print(f"Notice: Could not query previous workflow runs via GitHub API: {exc}")

    return ""


def determine_commits():
    head = os.environ.get("HEAD_SHA", "").strip()
    if not head:
        head = run_git("rev-parse", "HEAD").strip()

    base = find_last_successful_commit()
    if base:
        print(f"Using last successful workflow run commit as base: {base}")
        return base, head

    base = os.environ.get("BASE_SHA", "").strip()

    if not base or set(base) == {"0"}:
        try:
            base = run_git("rev-parse", f"{head}^").strip()
        except subprocess.CalledProcessError:
            base = ""

    return base, head


def changed_paths(base, head):
    if base:
        output = run_git(
            "diff",
            "--name-only",
            "--diff-filter=ACDMRT",
            base,
            head,
            "--",
        )
    else:
        output = run_git(
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-only",
            "-r",
            head,
        )

    return sorted({
        line.strip()
        for line in output.splitlines()
        if line.strip()
    })


def get_diff(base, head, paths):
    if not paths:
        return ""

    if base:
        args = [
            "diff",
            "--no-ext-diff",
            "--unified=3",
            base,
            head,
            "--",
            *paths,
        ]
    else:
        args = [
            "show",
            "--format=",
            "--root",
            "--no-ext-diff",
            "--unified=3",
            head,
            "--",
            *paths,
        ]

    return run_git(*args)


def read_changed_sources(paths):
    pieces = []
    source_map = {}
    total = 0

    for relative in paths:
        path = ROOT / relative

        try:
            path.resolve().relative_to(ROOT.resolve())
        except ValueError:
            continue

        if path.is_symlink() or not path.is_file():
            continue

        try:
            raw = path.read_bytes()
        except OSError:
            continue

        if b"\x00" in raw:
            continue

        text = raw.decode("utf-8", errors="replace")

        if len(text) > MAX_SOURCE_FILE_CHARS:
            pieces.append(
                f"FILE: {relative}\n"
                "[File omitted because it exceeds the context limit.]\n"
            )
            continue

        safe_text = redact(text)

        if total + len(safe_text) > MAX_SOURCE_CONTEXT_CHARS:
            pieces.append(
                f"FILE: {relative}\n"
                "[File omitted because the total context limit was reached.]\n"
            )
            continue

        source_map[relative] = safe_text
        pieces.append(f"FILE: {relative}\n{safe_text}\n")
        total += len(safe_text)

    return "\n".join(pieces), source_map


SCHEMA = {
    "type": "object",
    "properties": {
        "update_needed": {"type": "boolean"},
        "summary": {"type": "string"},
        "edits": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {
                        "type": "string",
                        "enum": ["README.md", "index.html"],
                    },
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                    "replacement": {"type": "string"},
                },
                "required": ["file", "start_line", "end_line", "replacement"],
                "additionalProperties": False,
            },
        },
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "quote": {"type": "string"},
                    "supports": {"type": "string"},
                },
                "required": ["path", "quote", "supports"],
                "additionalProperties": False,
            },
        },
    },
    "required": [
        "update_needed",
        "summary",
        "edits",
        "evidence",
    ],
    "additionalProperties": False,
}


SYSTEM_PROMPT = """
You are a documentation auditor for Tether (Windows C++ / C# Service / Android Kotlin).

CRITICAL DIRECTIVE: CONSERVE TOKENS.
Never output full documents. You only output precise line-range edits.
Default to update_needed = false and edits = [].

STRICT ABSTENTION RULES (update_needed = false):
- Do NOT update docs for bug fixes, error handling, or performance/stability tweaks.
- Do NOT update docs for internal refactoring, helper classes, or code cleanup.
- Do NOT update docs for unit tests, GitHub Actions CI/CD workflows, or Gradle build scripts.
- Do NOT update docs for internal IPC/network protocol changes unless user configuration flags change.
- If no user-visible feature, command, or documented architecture was altered, ABSTAIN.

LINE EDIT RULES (When update_needed = true):
- The documents are supplied with 1-based line numbers (e.g., '  42 | ## Installation').
- Use exact 1-based inclusive indices:
  * To replace line 42: start_line = 42, end_line = 42
  * To replace lines 42 to 45: start_line = 42, end_line = 45
  * To delete line 42: start_line = 42, end_line = 42, replacement = ""
  * To insert text before line 42 without deleting it: start_line = 42, end_line = 41
- Keep replacement strings strictly limited to the necessary markdown or HTML lines.
- Edits for the same file must not have overlapping line ranges.
- Do not make purely cosmetic, reformatting, or stylistic changes.

Return ONLY a valid JSON object matching the schema. No markdown fences outside the JSON.
"""


def apply_line_edits(original_content, edits):
    """Apply targeted line edits in descending order to preserve line indexing."""
    lines = original_content.splitlines(keepends=True)
    if not lines and original_content:
        lines = [original_content]

    # Sort descending by start_line to avoid invalidating subsequent line positions
    sorted_edits = sorted(
        edits,
        key=lambda item: (item["start_line"], item["end_line"]),
        reverse=True,
    )

    last_start = float("inf")
    for edit in sorted_edits:
        start = edit["start_line"]
        end = edit["end_line"]
        if start < 1:
            raise RuntimeError(f"start_line ({start}) must be >= 1.")
        if end < start - 1:
            raise RuntimeError(f"end_line ({end}) cannot be less than start_line - 1.")
        if end >= last_start:
            raise RuntimeError(
                f"Overlapping line edits detected between range {start}-{end} and {last_start}."
            )
        last_start = start

    for edit in sorted_edits:
        start = edit["start_line"]
        end = edit["end_line"]
        replacement = edit["replacement"]

        if replacement and not replacement.endswith("\n"):
            replacement += "\n"

        start_idx = min(start - 1, len(lines))
        end_idx = min(end, len(lines))

        rep_lines = replacement.splitlines(keepends=True) if replacement else []
        lines[start_idx:end_idx] = rep_lines

    return "".join(lines)


def parse_model_content(content, done_reason):
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("Ollama returned an empty response.")

    cleaned = content.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    unfenced = re.sub(r"\A```(?:json)?\s*", "", cleaned, count=1, flags=re.IGNORECASE)
    unfenced = re.sub(r"\s*```\s*\Z", "", unfenced, count=1)

    try:
        return json.loads(unfenced)
    except json.JSONDecodeError:
        pass

    start = unfenced.find("{")
    if start >= 0:
        try:
            answer, end = json.JSONDecoder().raw_decode(unfenced[start:])
            trailing = unfenced[start + end:].strip()
            if not trailing or trailing in ("```",):
                return answer
        except json.JSONDecodeError:
            pass

    raise RuntimeError(
        f"Ollama response could not be parsed as JSON (finish reason: {done_reason or 'unknown'})."
    )


def ask_ollama(model, payload):
    api_key = os.environ.get("OLLAMA_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("Missing OLLAMA_API_KEY. Add it as a GitHub Actions secret.")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
    ]

    body = {
        "model": model,
        "messages": messages,
        "stream": False,
        "format": SCHEMA,
        "options": {
            "temperature": 0,
            "num_predict": 4096,  # Line diffs only require small completion allowances
        },
    }

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=240) as response:
            response_body = response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Ollama API returned HTTP {exc.code}. Check key or quota.") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach Ollama Cloud: {exc.reason}") from None
    except TimeoutError:
        raise RuntimeError("Ollama Cloud request timed out.") from None

    try:
        result = json.loads(response_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise RuntimeError("Ollama returned an invalid response body.") from None

    message = result.get("message", {})
    content = message.get("content", "")
    done_reason = result.get("done_reason", "unknown")

    if done_reason == "length":
        print(f"Warning: Model response reached length limit ({len(content)} chars). Abstaining.")
        return {
            "update_needed": False,
            "summary": "Model output truncated. Abstaining safely.",
            "edits": [],
            "evidence": [],
        }

    return parse_model_content(content, done_reason)


def validate_and_apply(answer, paths, diff, source_map, original):
    if not isinstance(answer, dict):
        raise RuntimeError("AI response is not a JSON object.")

    if not answer.get("update_needed", False):
        return False, original

    edits = answer.get("edits", [])
    if not isinstance(edits, list) or not edits:
        return False, original

    evidence = answer.get("evidence", [])
    if not isinstance(evidence, list) or not evidence:
        raise RuntimeError("Model proposed line edits without providing evidence.")

    for item in evidence:
        path = item.get("path")
        quote = item.get("quote", "")
        if path not in paths:
            raise RuntimeError(f"Evidence refers to an unanalyzed file: {path}")
        if len(quote.strip()) < 10:
            raise RuntimeError("Evidence quote missing or too short.")

        source_text = source_map.get(path, "")
        if quote not in source_text and quote not in diff:
            raise RuntimeError(f"Evidence quote could not be verified in {path}.")

    updated = dict(original)
    edits_by_file = {"README.md": [], "index.html": []}

    for edit in edits:
        target_file = edit.get("file")
        if target_file not in edits_by_file:
            raise RuntimeError(f"Unknown target file for edit: {target_file}")
        edits_by_file[target_file].append(edit)

    has_material_changes = False

    for target_file, file_edits in edits_by_file.items():
        if not file_edits:
            continue

        new_content = apply_line_edits(original[target_file], file_edits)

        if len(new_content) > MAX_DOCUMENT_CHARS:
            raise RuntimeError(f"{target_file} exceeds document character limits after edits.")

        if target_file == "index.html":
            if not re.search(r"<!doctype\s+html", new_content, re.IGNORECASE):
                raise RuntimeError("Edits removed HTML doctype. Abstaining.")
            if not re.search(r"</html\s*>", new_content, re.IGNORECASE):
                raise RuntimeError("Edits resulted in unclosed HTML document.")

        if new_content != original[target_file]:
            updated[target_file] = new_content
            has_material_changes = True

    return has_material_changes, updated


def main():
    for relative, path in DOCS.items():
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"Required file missing or unsafe: {relative}")

    original = {
        name: path.read_text(encoding="utf-8")
        for name, path in DOCS.items()
    }

    base, head = determine_commits()
    all_paths = changed_paths(base, head)

    source_paths = [
        path for path in all_paths
        if path not in IGNORED_EXACT
        and not any(path.startswith(prefix) for prefix in IGNORED_DIR_PREFIXES)
        and not any(path.endswith(ext) for ext in IGNORED_EXTENSIONS)
    ]

    if not source_paths:
        print("No relevant source changes. Documentation untouched.")
        set_output("changed", "false")
        write_summary([
            "## AI documentation review",
            "No relevant source changes were found. No PR was created.",
        ])
        return

    raw_diff = get_diff(base, head, source_paths)

    if len(raw_diff) > MAX_DIFF_CHARS:
        print(
            f"Source diff ({len(raw_diff)} chars) exceeds safe limit of {MAX_DIFF_CHARS}. "
            "Abstaining from automated doc updates."
        )
        set_output("changed", "false")
        write_summary([
            "## AI documentation review",
            f"- Base SHA: `{base}`",
            f"- Head SHA: `{head}`",
            f"- Diff length: `{len(raw_diff)}` characters (Limit: `{MAX_DIFF_CHARS}`)",
            "",
            "Diff exceeds safe limit. Workflow skipped cleanly without failing.",
        ])
        return

    diff = redact(raw_diff)
    source_context, source_map = read_changed_sources(source_paths)

    payload = {
        "repository": "tirthsaraiya29/Tether",
        "branch": os.environ.get("BRANCH_NAME", ""),
        "base_commit": base or "(initial commit)",
        "head_commit": head,
        "changed_source_files": source_paths,
        "source_diff": diff,
        "changed_source_contents": source_context,
        "current_readme_md_numbered": format_numbered_lines(original["README.md"]),
        "current_index_html_numbered": format_numbered_lines(original["index.html"]),
    }

    model = os.environ.get("OLLAMA_MODEL", "gpt-oss:120b").strip()
    if not model:
        raise RuntimeError("OLLAMA_MODEL cannot be empty.")

    print(
        f"Auditing {len(source_paths)} changed files with Ollama ({base[:7] if base else 'root'}..{head[:7]})."
    )

    answer = ask_ollama(model, payload)
    should_write, updated_docs = validate_and_apply(
        answer,
        source_paths,
        diff,
        source_map,
        original,
    )

    summary_lines = [
        "## AI documentation review",
        f"- Model: `{model}`",
        f"- Branch: `{payload['branch']}`",
        f"- Base Commit: `{base}`",
        f"- Head Commit: `{head}`",
        f"- Decision: {'proposed line changes' if should_write else 'no changes'}",
    ]

    if answer.get("summary", "").strip():
        summary_lines.extend(["", "### Model rationale", answer["summary"]])

    if not should_write:
        print("No documentation updates required.")
        set_output("changed", "false")
        write_summary(summary_lines)
        return

    for filename, content in updated_docs.items():
        if content != original[filename]:
            DOCS[filename].write_text(content, encoding="utf-8", newline="\n")
            print(f"Applied targeted line updates to {filename}")

    set_output("changed", "true")
    write_summary(summary_lines)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Documentation automation failed: {exc}", file=sys.stderr)
        sys.exit(1)