#!/usr/bin/env python3
"""Parse Vulnhalla _final.json results into a summary JSON."""
import json
import re
import sys
from pathlib import Path

def parse(case_dir: str) -> None:
    case_dir = Path(case_dir)
    results_dir = case_dir / "vulnhalla_results"
    summary = {
        "status": "done",
        "total_issues": 0,
        "true_positives": 0,
        "false_positives": 0,
        "needs_more_data": 0,
        "issue_types": {},
    }

    if not results_dir.exists():
        summary["status"] = "no_results"
        (case_dir / "vulnhalla_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )
        return

    for issue_dir in sorted(results_dir.iterdir()):
        if not issue_dir.is_dir():
            continue
        itype = issue_dir.name
        ts = {"true": 0, "false": 0, "more": 0}

        for ff in sorted(issue_dir.glob("*_final.json")):
            try:
                raw = ff.read_text(encoding="utf-8", errors="ignore")
                idx = raw.rfind("'role': 'assistant'")
                if idx < 0:
                    continue
                llm = raw[idx:]
                codes = re.findall(r'\b(1337|1007|7331|3713)\b', llm)
                if not codes:
                    st = "more"
                elif codes[-1] == "1337":
                    st = "true"
                elif codes[-1] == "1007":
                    st = "false"
                else:
                    st = "more"

                ts[st] += 1
                if st == "true":
                    summary["true_positives"] += 1
                elif st == "false":
                    summary["false_positives"] += 1
                else:
                    summary["needs_more_data"] += 1
                summary["total_issues"] += 1
            except OSError:
                continue

        summary["issue_types"][itype] = ts

    (case_dir / "vulnhalla_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

if __name__ == "__main__":
    parse(sys.argv[1])
