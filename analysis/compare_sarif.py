#!/usr/bin/env python3
"""
Compare existing before.sarif and after.sarif with AI-edited file list and write
AI-introduced findings report. Use this when you have already produced SARIF files
(e.g. by running CodeQL manually) and only need the diff attribution.

Usage:
  python compare_sarif.py --diff-json path/to/diffs/<sha>.json --before path/to/before.sarif --after path/to/after.sarif --output report.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sarif_compare import ai_introduced_findings


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare before/after SARIF and attribute findings to AI-edited files")
    ap.add_argument("--diff-json", type=Path, required=True, help="Path to AI commit diff JSON (has files[].filename)")
    ap.add_argument("--before", type=Path, required=True, help="SARIF from repo at parent commit")
    ap.add_argument("--after", type=Path, required=True, help="SARIF from repo at AI commit")
    ap.add_argument("--output", type=Path, required=True, help="Output report JSON path")
    ap.add_argument("--repo-root-name", type=str, default="", help="Optional repo dir name for path normalization")
    args = ap.parse_args()

    diff_path = args.diff_json
    if not diff_path.exists():
        print(f"Diff not found: {diff_path}", file=sys.stderr)
        sys.exit(1)
    diff = json.loads(diff_path.read_text(encoding="utf-8"))
    files = diff.get("files") or []
    ai_edited = [f.get("filename") for f in files if f.get("filename")]

    # Reconstruct changed line numbers in the after revision from unified diff hunks.
    changed_lines = {}
    for f in files:
        filename = f.get("filename")
        patch = f.get("patch")
        if not filename or not patch:
            continue
        norm_name = filename.replace("\\", "/").strip("/")
        line_set = changed_lines.setdefault(norm_name, set())

        new_line = None
        for raw in patch.splitlines():
            if raw.startswith("@@"):
                m = re.search(r"\+(\d+)(?:,(\d+))?", raw)
                if not m:
                    new_line = None
                    continue
                new_line = int(m.group(1))
                continue

            if new_line is None:
                continue

            if raw.startswith("+") and not raw.startswith("+++"):
                line_set.add(new_line)
                new_line += 1
            elif raw.startswith("-") and not raw.startswith("---"):
                continue
            else:
                new_line += 1

    introduced = ai_introduced_findings(
        args.after,
        ai_edited,
        changed_lines,
        repo_root_name=args.repo_root_name,
    )
    report = {
        "repo": diff.get("repo"),
        "sha": diff.get("sha"),
        "html_url": diff.get("html_url"),
        "ai_edited_files": ai_edited,
        "ai_introduced_findings": introduced,
        "num_ai_introduced": len(introduced),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {args.output} (num_ai_introduced={len(introduced)})", file=sys.stderr)


if __name__ == "__main__":
    main()
