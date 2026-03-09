#!/usr/bin/env python3
"""Print final summary table across all cases."""
import json
import sys
from pathlib import Path


def main(base_dir: str) -> None:
    base = Path(base_dir)
    results = []

    for case_dir in sorted(base.iterdir()):
        comp_file = case_dir / "comparison.json"
        if not comp_file.exists():
            continue
        try:
            comp = json.loads(comp_file.read_text(encoding="utf-8"))
            results.append(comp)
        except Exception:
            continue

    if not results:
        print("No results found.")
        return

    # Print table
    print(f"{'Repo':<45} {'Vuln Type':<25} {'Orig Agent':<10} "
          f"{'Orig TP':<8} {'Gen TP':<8} {'Gen FP':<8} {'CodeQL':<8} {'Assessment'}")
    print("-" * 160)

    for r in results:
        repo = r.get("repo", "?")
        vtype = r.get("vuln_type", "?")
        agent = r.get("original_agent", "?")
        orig_tp = r["original"].get("true_positives", 0)
        gen = r["opencode_generated"]
        gen_tp = gen.get("true_positives", 0)
        gen_fp = gen.get("false_positives", 0)
        codeql = gen.get("codeql_issues", 0)
        assessment = r.get("assessment", "?")

        print(f"{repo:<45} {vtype:<25} {agent:<10} "
              f"{orig_tp:<8} {gen_tp:<8} {gen_fp:<8} {codeql:<8} {assessment}")

    # Counts
    print()
    vuln_same = sum(1 for r in results if r.get("assessment", "").startswith("VULNERABLE_SAME"))
    vuln_diff = sum(1 for r in results if r.get("assessment", "").startswith("VULNERABLE_DIFFERENT"))
    secure = sum(1 for r in results if r.get("assessment", "").startswith("SECURE"))
    print(f"Vulnerable (same type):      {vuln_same}")
    print(f"Vulnerable (different type): {vuln_diff}")
    print(f"Secure:                      {secure}")
    print(f"Total:                       {len(results)}")

    # Save as JSON
    report = {
        "total_cases": len(results),
        "vulnerable_same": vuln_same,
        "vulnerable_different": vuln_diff,
        "secure": secure,
        "results": results,
    }
    report_path = Path(base_dir) / "summary_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nSaved: {report_path}")


if __name__ == "__main__":
    main(sys.argv[1])
