
#!/usr/bin/env python3
"""Export reproducible Git analytics for all fetched Tether refs."""

import csv
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

OUT = Path("reports")
OUT.mkdir(exist_ok=True)

# Adjust these after inspecting the actual Tether directory tree.
ANDROID_PATH = re.compile(
    r"(^|/)(android|app|mobile)/|"
    r"\.(kt|java|kts)$|AndroidManifest\.xml$|"
    r"(^|/)gradle/"
    , re.I
)
WINDOWS_PATH = re.compile(
    r"(^|/)(windows|win32|credentialprovider|desktopui)/|"
    r"\.(cs|csproj|sln|vcxproj|cpp|cxx|hpp|h|rc|wxs)$",
    re.I,
)

def run_git(*args):
    return subprocess.check_output(
        ["git", *args], text=True, errors="replace"
    )

def platform(path):
    a = bool(ANDROID_PATH.search(path))
    w = bool(WINDOWS_PATH.search(path))
    if a and w:
        return "shared"
    if a:
        return "android"
    if w:
        return "windows"
    return "other"

def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

# --all walks commits reachable from the refs present in this checkout.
# Each SHA appears once, even when reachable from multiple branches.
raw = run_git(
    "log", "--all",
    "--format=%x1e%H%x1f%cI%x1f%aI%x1f%an%x1f%s",
    "--numstat"
)

commits = {}
files = []
for block in raw.split("\x1e"):
    lines = block.strip("\n").splitlines()
    if not lines or "\x1f" not in lines[0]:
        continue

    parts = lines[0].split("\x1f", 4)
    if len(parts) != 5:
        continue

    sha, committed, authored, author, subject = parts
    if sha in commits:
        continue

    commit_files = []
    for line in lines[1:]:
        cols = line.split("\t", 2)
        if len(cols) != 3:
            continue
        add_s, del_s, path = cols

        # Binary files have '-' instead of line counts.
        adds = int(add_s) if add_s.isdigit() else 0
        dels = int(del_s) if del_s.isdigit() else 0
        item = {
            "sha": sha,
            "date": committed[:10],
            "path": path,
            "platform": platform(path),
            "additions": adds,
            "deletions": dels,
            "binary_or_unknown": not (
                add_s.isdigit() and del_s.isdigit()
            ),
        }
        commit_files.append(item)
        files.append(item)

    commits[sha] = {
        "sha": sha,
        "committed_at": committed,
        "authored_at": authored,
        "author": author,
        "subject": subject,
        "date": committed[:10],
        "files_changed": len(commit_files),
        "additions": sum(x["additions"] for x in commit_files),
        "deletions": sum(x["deletions"] for x in commit_files),
        "android_additions": sum(
            x["additions"] for x in commit_files
            if x["platform"] == "android"
        ),
        "android_deletions": sum(
            x["deletions"] for x in commit_files
            if x["platform"] == "android"
        ),
        "windows_additions": sum(
            x["additions"] for x in commit_files
            if x["platform"] == "windows"
        ),
        "windows_deletions": sum(
            x["deletions"] for x in commit_files
            if x["platform"] == "windows"
        ),
        "shared_files": sum(
            x["platform"] == "shared" for x in commit_files
        ),
        "other_files": sum(
            x["platform"] == "other" for x in commit_files
        ),
        "files": [x["path"] for x in commit_files],
    }

commit_rows = list(commits.values())
commit_rows.sort(key=lambda x: (x["committed_at"], x["sha"]))

write_csv(
    OUT / "commits.csv",
    [{k: v for k, v in c.items() if k != "files"}
     | {"files": " | ".join(c["files"])}
     for c in commit_rows],
    [
        "sha", "committed_at", "authored_at", "author", "subject",
        "date", "files_changed", "additions", "deletions",
        "android_additions", "android_deletions",
        "windows_additions", "windows_deletions",
        "shared_files", "other_files", "files",
    ],
)

write_csv(
    OUT / "file_changes.csv",
    files,
    ["sha", "date", "path", "platform", "additions",
     "deletions", "binary_or_unknown"],
)

daily = Counter(c["date"] for c in commit_rows)
daily_rows = [
    {"date": day, "commits": count}
    for day, count in sorted(daily.items())
]
write_csv(OUT / "daily_counts.csv", daily_rows, ["date", "commits"])

# These are candidate labels, not definitive feature classifications.
def candidate(subject):
    s = subject.lower()
    patterns = {
        "connection/pairing": r"connect|pair|handshake|tls|trust",
        "unlock/security": r"unlock|credential|biometric|auth|secure",
        "android": r"android|kotlin|foreground service|notification",
        "windows": r"windows|c#|wpf|service|credential provider",
        "ui": r"\bui\b|interface|layout|screen|theme|design",
        "bug fix": r"\bfix\b|bug|crash|regression|broken",
        "build/ci": r"build|gradle|workflow|codeql|pipeline",
        "docs": r"docs?|readme|documentation",
    }
    return [name for name, pattern in patterns.items()
            if re.search(pattern, s)]

for c in commit_rows:
    c["candidate_labels"] = candidate(c["subject"])

with (OUT / "commits.jsonl").open("w", encoding="utf-8") as f:
    for c in commit_rows:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")

totals = {
    "unique_commits": len(commit_rows),
    "days_with_commits": len(daily),
    "first_commit_date": min(daily, default=None),
    "last_commit_date": max(daily, default=None),
    "total_additions": sum(c["additions"] for c in commit_rows),
    "total_deletions": sum(c["deletions"] for c in commit_rows),
    "android_additions": sum(c["android_additions"] for c in commit_rows),
    "android_deletions": sum(c["android_deletions"] for c in commit_rows),
    "windows_additions": sum(c["windows_additions"] for c in commit_rows),
    "windows_deletions": sum(c["windows_deletions"] for c in commit_rows),
    "note": (
        "Commits are deduplicated by SHA across fetched refs. "
        "Merge commits may show zero file changes because Git's default "
        "log diff omits merge diffs. Platform rules are path heuristics. "
        "Binary changes have no meaningful line count."
    ),
}

(OUT / "summary.json").write_text(
    json.dumps(totals, indent=2), encoding="utf-8"
)
(OUT / "summary.md").write_text(
    "# Tether Git analytics\n\n" +
    "\n".join(f"- **{k.replace('_', ' ').title()}:** {v}"
              for k, v in totals.items()) +
    "\n\n## Daily commit counts\n\n" +
    "| Date | Commits |\n|---|---:|\n" +
    "\n".join(f"| {r['date']} | {r['commits']} |"
              for r in daily_rows) +
    "\n", encoding="utf-8"
)

print(json.dumps(totals, indent=2))
print(f"Reports written to {OUT.resolve()}")
