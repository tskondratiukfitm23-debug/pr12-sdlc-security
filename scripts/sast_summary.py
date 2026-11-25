"""Aggregate Semgrep / Bandit / pip-audit JSON reports into a Markdown summary and a security gate.

Usage:
    python scripts/sast_summary.py          # Markdown summary (for $GITHUB_STEP_SUMMARY)
    python scripts/sast_summary.py --gate   # exit 1 if blocking findings exist
Blocking = Semgrep ERROR, Bandit HIGH, any vulnerable dependency.
"""
import json
import sys
from pathlib import Path


def load(name):
    p = Path(name)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def collect():
    rows = []
    for r in load("semgrep.json").get("results", []):
        rows.append(("Semgrep", r["extra"].get("severity", "?"), r["check_id"].split(".")[-1],
                     f'{r["path"]}:{r["start"]["line"]}'))
    for r in load("bandit.json").get("results", []):
        rows.append(("Bandit", r["issue_severity"], f'{r["test_id"]} {r["test_name"]}',
                     f'{r["filename"]}:{r["line_number"]}'))
    for dep in load("pip-audit.json").get("dependencies", []):
        for v in dep.get("vulns", []):
            fix = ",".join(v.get("fix_versions", [])) or "-"
            rows.append(("pip-audit", "HIGH", f'{dep["name"]}=={dep["version"]} {v["id"]} (fix {fix})',
                         "requirements.txt"))
    return rows


def is_blocking(row):
    tool, sev = row[0], row[1].upper()
    return (tool == "Semgrep" and sev == "ERROR") or (tool == "Bandit" and sev == "HIGH") or tool == "pip-audit"


def main():
    rows = collect()
    block = [r for r in rows if is_blocking(r)]
    if "--gate" in sys.argv:
        for r in block:
            print("BLOCKING:", " | ".join(r))
        print(f"Security gate: {len(block)} blocking of {len(rows)} findings")
        sys.exit(1 if block else 0)
    print("## SAST summary\n")
    print(f"Total findings: **{len(rows)}**, blocking: **{len(block)}**\n")
    print("| Tool | Severity | Rule | Location |\n|---|---|---|---|")
    for r in rows:
        print("| " + " | ".join(r) + " |")


if __name__ == "__main__":
    main()
