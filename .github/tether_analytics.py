import csv
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
OUT = Path("reports")
OUT.mkdir(exist_ok=True)
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
LANG_BY_EXT = {
    ".kt": "Kotlin", ".kts": "Kotlin",
    ".cs": "C#", ".csx": "C#", ".csproj": "C#", ".sln": "C#",
    ".cpp": "C++", ".cxx": "C++", ".cc": "C++", ".c++": "C++",
    ".hpp": "C++", ".hxx": "C++", ".hh": "C++", ".h++": "C++",
    ".inl": "C++", ".ipp": "C++", ".tpp": "C++",
    ".c": "C", ".h": "C",
    ".reg": "Registry",
    ".bat": "Batch",
    ".py": "Python",
    ".md": "Markdown",
}
COMMENT_PREFIXES = {
    "Kotlin": ("//", "/*", "*"),
    "C#": ("//", "/*", "*"),
    "C++": ("//", "/*", "*"),
    "C": ("//", "/*", "*"),
    "Python": ("#",),
    "Registry": (";",),
    "Batch": ("::", "REM ", "rem "),
    "Markdown": (),
}
def run_git(*args):
    return subprocess.check_output(["git", *args], text=True, errors="replace")
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
def language_of(rel):
    ext = Path(rel).suffix.lower()
    return LANG_BY_EXT.get(ext)
def count_loc(text, prefixes):
    total = blank = comment = code = 0
    for line in text.splitlines():
        total += 1
        s = line.strip()
        if not s:
            blank += 1
        elif prefixes and any(s.startswith(p) for p in prefixes):
            comment += 1
        else:
            code += 1
    return total, code, comment, blank
def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
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
        adds = int(add_s) if add_s.isdigit() else 0
        dels = int(del_s) if del_s.isdigit() else 0
        item = {
            "sha": sha, "date": committed[:10], "path": path,
            "platform": platform(path),
            "additions": adds, "deletions": dels,
            "binary_or_unknown": not (add_s.isdigit() and del_s.isdigit()),
        }
        commit_files.append(item)
        files.append(item)
    commits[sha] = {
        "sha": sha, "committed_at": committed, "authored_at": authored,
        "author": author, "subject": subject, "date": committed[:10],
        "files_changed": len(commit_files),
        "additions": sum(x["additions"] for x in commit_files),
        "deletions": sum(x["deletions"] for x in commit_files),
        "android_additions": sum(x["additions"] for x in commit_files if x["platform"] == "android"),
        "android_deletions": sum(x["deletions"] for x in commit_files if x["platform"] == "android"),
        "windows_additions": sum(x["additions"] for x in commit_files if x["platform"] == "windows"),
        "windows_deletions": sum(x["deletions"] for x in commit_files if x["platform"] == "windows"),
        "shared_files": sum(x["platform"] == "shared" for x in commit_files),
        "other_files": sum(x["platform"] == "other" for x in commit_files),
        "files": [x["path"] for x in commit_files],
    }
commit_rows = list(commits.values())
commit_rows.sort(key=lambda x: (x["committed_at"], x["sha"]))
write_csv(
    OUT / "commits.csv",
    [{k: v for k, v in c.items() if k != "files"} | {"files": " | ".join(c["files"])} for c in commit_rows],
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
    ["sha", "date", "path", "platform", "additions", "deletions", "binary_or_unknown"],
)
daily = Counter(c["date"] for c in commit_rows)
daily_rows = [{"date": day, "commits": count} for day, count in sorted(daily.items())]
write_csv(OUT / "daily_counts.csv", daily_rows, ["date", "commits"])
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
    return [name for name, pattern in patterns.items() if re.search(pattern, s)]
for c in commit_rows:
    c["candidate_labels"] = candidate(c["subject"])
with (OUT / "commits.jsonl").open("w", encoding="utf-8") as f:
    for c in commit_rows:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")
per_file_loc = []
by_lang = defaultdict(lambda: {"files": 0, "total": 0, "code": 0, "comment": 0, "blank": 0})
by_plat = defaultdict(lambda: {"files": 0, "total": 0, "code": 0, "comment": 0, "blank": 0})
for rel in run_git("ls-files").splitlines():
    p = Path(rel)
    if not p.is_file():
        continue
    lang = language_of(rel)
    if lang is None:
        continue
    try:
        data = p.read_bytes()
    except OSError:
        continue
    if b"\x00" in data[:8192]:
        continue
    text = data.decode("utf-8", errors="replace")
    prefixes = COMMENT_PREFIXES.get(lang, ())
    total, code, comment, blank = count_loc(text, prefixes)
    plat = platform(rel)
    per_file_loc.append({
        "path": rel, "platform": plat, "language": lang,
        "total_lines": total, "code_lines": code,
        "comment_lines": comment, "blank_lines": blank,
        "lines_without_comments": total - comment,
        "lines_without_blank": total - blank,
    })
    for d in (by_lang[lang], by_plat[plat]):
        d["files"] += 1
        d["total"] += total
        d["code"] += code
        d["comment"] += comment
        d["blank"] += blank
write_csv(
    OUT / "loc_by_file.csv",
    per_file_loc,
    [
        "path", "platform", "language", "total_lines", "code_lines",
        "comment_lines", "blank_lines",
        "lines_without_comments", "lines_without_blank",
    ],
)
def loc_row(name, d):
    return {
        "name": name, "files": d["files"],
        "total_lines": d["total"], "code_lines": d["code"],
        "comment_lines": d["comment"], "blank_lines": d["blank"],
        "lines_without_comments": d["total"] - d["comment"],
        "lines_without_blank": d["total"] - d["blank"],
    }
lang_rows = sorted((loc_row(k, v) for k, v in by_lang.items()), key=lambda r: -r["total_lines"])
plat_rows = sorted((loc_row(k, v) for k, v in by_plat.items()), key=lambda r: -r["total_lines"])
loc_fields = [
    "name", "files", "total_lines", "code_lines", "comment_lines",
    "blank_lines", "lines_without_comments", "lines_without_blank",
]
write_csv(OUT / "loc_by_language.csv", lang_rows, loc_fields)
write_csv(OUT / "loc_by_platform.csv", plat_rows, loc_fields)
def sum_loc(rows):
    return {
        "files": sum(r["files"] for r in rows),
        "total_lines": sum(r["total_lines"] for r in rows),
        "code_lines": sum(r["code_lines"] for r in rows),
        "comment_lines": sum(r["comment_lines"] for r in rows),
        "blank_lines": sum(r["blank_lines"] for r in rows),
        "lines_without_comments": sum(r["lines_without_comments"] for r in rows),
        "lines_without_blank": sum(r["lines_without_blank"] for r in rows),
    }
loc_totals = sum_loc(lang_rows)
android_loc = sum_loc([r for r in plat_rows if r["name"] == "android"])
windows_loc = sum_loc([r for r in plat_rows if r["name"] == "windows"])
shared_loc = sum_loc([r for r in plat_rows if r["name"] == "shared"])
other_loc = sum_loc([r for r in plat_rows if r["name"] == "other"])
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
        "Binary changes have no meaningful line count. LOC is restricted "
        "to the extensions used by the languages GitHub reports for this "
        "repo (Kotlin, C#, C++, C) plus .reg, .bat, .py, and .md. LOC is "
        "computed on the current working tree via git ls-files; comment "
        "detection is line-prefix based (block-comment continuation lines "
        "may be counted as code). Binary files are skipped."
    ),
}
summary = dict(totals)
summary["loc_total"] = loc_totals
summary["loc_android"] = android_loc
summary["loc_windows"] = windows_loc
summary["loc_shared"] = shared_loc
summary["loc_other"] = other_loc
(OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
md = ["# Tether Git analytics", "", "## Git", ""]
for k, v in totals.items():
    md.append(f"- **{k.replace('_', ' ').title()}:** {v}")
md += ["", "## Lines of code", "", "### Total (selected extensions only)", ""]
for k, v in loc_totals.items():
    md.append(f"- **{k.replace('_', ' ').title()}:** {v}")
md += ["", "### Android", ""]
for k, v in android_loc.items():
    md.append(f"- **{k.replace('_', ' ').title()}:** {v}")
md += ["", "### Windows", ""]
for k, v in windows_loc.items():
    md.append(f"- **{k.replace('_', ' ').title()}:** {v}")
md += ["", "### Shared", ""]
for k, v in shared_loc.items():
    md.append(f"- **{k.replace('_', ' ').title()}:** {v}")
md += ["", "### Other", ""]
for k, v in other_loc.items():
    md.append(f"- **{k.replace('_', ' ').title()}:** {v}")
md += [
    "", "### LOC by language", "",
    "| Language | Files | Total | Code | Comments | Blank | No comments | No blank |",
    "|---|---:|---:|---:|---:|---:|---:|---:|",
]
for r in lang_rows:
    md.append(
        f"| {r['name']} | {r['files']} | {r['total_lines']} | {r['code_lines']} "
        f"| {r['comment_lines']} | {r['blank_lines']} "
        f"| {r['lines_without_comments']} | {r['lines_without_blank']} |"
    )
md += [
    "", "### LOC by platform", "",
    "| Platform | Files | Total | Code | Comments | Blank | No comments | No blank |",
    "|---|---:|---:|---:|---:|---:|---:|---:|",
]
for r in plat_rows:
    md.append(
        f"| {r['name']} | {r['files']} | {r['total_lines']} | {r['code_lines']} "
        f"| {r['comment_lines']} | {r['blank_lines']} "
        f"| {r['lines_without_comments']} | {r['lines_without_blank']} |"
    )
md += ["", "## Daily commit counts", "", "| Date | Commits |", "|---|---:|"]
for r in daily_rows:
    md.append(f"| {r['date']} | {r['commits']} |")
md.append("")
(OUT / "summary.md").write_text("\n".join(md), encoding="utf-8")
print(json.dumps(summary, indent=2))
print(f"Reports written to {OUT.resolve()}")