#!/usr/bin/env python3
"""
Script 3: Aggregate all Vulnhalla results into a single summary JSON/CSV.

Walks the output directory from Scripts 1 & 2, reads commit_info.json and
vulnhalla_summary.json for each commit, and produces:
  - ai_commit_vulnerability_summary.json  (full structured output)
  - ai_commit_vulnerability_summary.csv   (flat per-finding rows)

Usage:
    python summarize_results.py \
        --db-root ./ai_commit_dbs \
        --output-json ai_commit_vulnerability_summary.json \
        --output-csv ai_commit_vulnerability_summary.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def collect_results(db_root: Path) -> List[Dict[str, Any]]:
    """
    Walk the output directory and collect all commit results.
    Returns list of per-commit result dicts.
    """
    results = []
    if not db_root.exists():
        return results

    for repo_slug_dir in sorted(db_root.iterdir()):
        if not repo_slug_dir.is_dir() or repo_slug_dir.name in ("workspace", "errors.jsonl", "vulnhalla_errors.jsonl"):
            continue
        for sha_dir in sorted(repo_slug_dir.iterdir()):
            if not sha_dir.is_dir():
                continue

            commit_info_path = sha_dir / "commit_info.json"
            vulnhalla_summary_path = sha_dir / "vulnhalla_summary.json"

            if not commit_info_path.exists():
                continue

            try:
                commit_info = json.loads(commit_info_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            vulnhalla_summary = None
            if vulnhalla_summary_path.exists():
                try:
                    vulnhalla_summary = json.loads(
                        vulnhalla_summary_path.read_text(encoding="utf-8")
                    )
                except (json.JSONDecodeError, OSError):
                    pass

            results.append({
                "commit_info": commit_info,
                "vulnhalla_summary": vulnhalla_summary,
                "repo_slug": repo_slug_dir.name,
                "sha_dir": str(sha_dir),
            })

    return results


def build_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the aggregate summary JSON from all results."""
    total_commits = len(results)
    commits_with_dbs = 0
    commits_with_vulnhalla = 0
    total_issues = 0
    total_tp = 0
    total_fp = 0
    total_more = 0

    by_language: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"commits": 0, "issues": 0, "true_positives": 0,
                 "false_positives": 0, "needs_more_data": 0}
    )
    by_agent: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"commits": 0, "issues": 0, "true_positives": 0,
                 "false_positives": 0, "needs_more_data": 0}
    )
    findings: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for result in results:
        ci = result["commit_info"]
        vs = result["vulnhalla_summary"]
        repo = ci.get("repo", "")
        sha = ci.get("sha", "")
        agents = ci.get("agents", [])
        detected_langs = ci.get("detected_languages", [])

        # Check if DB creation succeeded for any language
        db_results = ci.get("db_results", {})
        has_successful_db = any(
            r.get("success") for r in db_results.values()
        )
        if has_successful_db:
            commits_with_dbs += 1

        # Track errors
        failed_dbs = {
            lang: r.get("error", "unknown")
            for lang, r in db_results.items()
            if not r.get("success")
        }
        if failed_dbs:
            errors.append({
                "repo": repo,
                "sha": sha,
                "stage": "codeql_db_creation",
                "failed_languages": failed_dbs,
            })

        if vs is None:
            continue

        commits_with_vulnhalla += 1
        commit_issues = vs.get("total_issues", 0)
        commit_tp = vs.get("true_positives", 0)
        commit_fp = vs.get("false_positives", 0)
        commit_more = vs.get("needs_more_data", 0)
        lang = vs.get("language", "unknown")

        total_issues += commit_issues
        total_tp += commit_tp
        total_fp += commit_fp
        total_more += commit_more

        # By language
        by_language[lang]["commits"] += 1
        by_language[lang]["issues"] += commit_issues
        by_language[lang]["true_positives"] += commit_tp
        by_language[lang]["false_positives"] += commit_fp
        by_language[lang]["needs_more_data"] += commit_more

        # By agent
        for agent in agents:
            by_agent[agent]["commits"] += 1
            by_agent[agent]["issues"] += commit_issues
            by_agent[agent]["true_positives"] += commit_tp
            by_agent[agent]["false_positives"] += commit_fp
            by_agent[agent]["needs_more_data"] += commit_more

        # Individual findings
        for issue_type, type_data in vs.get("issue_types", {}).items():
            for finding in type_data.get("findings", []):
                findings.append({
                    "repo": repo,
                    "sha": sha,
                    "agents": agents,
                    "language": lang,
                    "issue_type": issue_type.replace("_", " "),
                    "file": finding.get("file", ""),
                    "line": finding.get("line", 0),
                    "status": finding.get("status", ""),
                    "llm_explanation": finding.get("llm_explanation", ""),
                })

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_commits_crawled": total_commits,
        "total_commits_with_dbs": commits_with_dbs,
        "total_commits_analyzed": commits_with_vulnhalla,
        "total_issues_found": total_issues,
        "total_true_positives": total_tp,
        "total_false_positives": total_fp,
        "total_needs_more_data": total_more,
        "by_language": dict(by_language),
        "by_agent": dict(by_agent),
        "findings": findings,
        "errors_summary": {
            "total_errors": len(errors),
            "errors": errors[:100],  # Cap to avoid huge output
        },
    }
    return summary


def write_csv(findings: List[Dict[str, Any]], output_path: Path) -> None:
    """Write findings as a flat CSV file."""
    if not findings:
        print("No findings to write to CSV.", file=sys.stderr)
        return

    fieldnames = [
        "repo", "sha", "agents", "language", "issue_type",
        "file", "line", "status", "llm_explanation",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            row = dict(finding)
            # Convert agents list to comma-separated string
            row["agents"] = ",".join(row.get("agents", []))
            writer.writerow(row)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Aggregate Vulnhalla results into summary JSON/CSV"
    )
    ap.add_argument(
        "--db-root", type=Path,
        default=Path(__file__).resolve().parent / "ai_commit_dbs",
        help="Root directory containing repo_slug/sha/ structures",
    )
    ap.add_argument(
        "--output-json", type=Path,
        default=Path(__file__).resolve().parent / "ai_commit_vulnerability_summary.json",
        help="Output JSON file path",
    )
    ap.add_argument(
        "--output-csv", type=Path,
        default=Path(__file__).resolve().parent / "ai_commit_vulnerability_summary.csv",
        help="Output CSV file path",
    )
    args = ap.parse_args()

    db_root = args.db_root.resolve()
    print(f"Scanning results under: {db_root}", file=sys.stderr)

    results = collect_results(db_root)
    print(f"Found {len(results)} commits with data.", file=sys.stderr)

    if not results:
        print("No results to summarize.", file=sys.stderr)
        return

    summary = build_summary(results)

    # Print top-level stats
    print(f"\nSummary:", file=sys.stderr)
    print(f"  Commits crawled:     {summary['total_commits_crawled']}", file=sys.stderr)
    print(f"  Commits with DBs:    {summary['total_commits_with_dbs']}", file=sys.stderr)
    print(f"  Commits analyzed:    {summary['total_commits_analyzed']}", file=sys.stderr)
    print(f"  Total issues:        {summary['total_issues_found']}", file=sys.stderr)
    print(f"  True positives:      {summary['total_true_positives']}", file=sys.stderr)
    print(f"  False positives:     {summary['total_false_positives']}", file=sys.stderr)
    print(f"  Needs more data:     {summary['total_needs_more_data']}", file=sys.stderr)

    if summary["by_language"]:
        print(f"\n  By language:", file=sys.stderr)
        for lang, stats in sorted(summary["by_language"].items()):
            print(
                f"    {lang:15s} commits={stats['commits']:4d}  "
                f"issues={stats['issues']:4d}  "
                f"TP={stats['true_positives']:3d}  "
                f"FP={stats['false_positives']:3d}  "
                f"more={stats['needs_more_data']:3d}",
                file=sys.stderr,
            )

    if summary["by_agent"]:
        print(f"\n  By agent:", file=sys.stderr)
        for agent, stats in sorted(summary["by_agent"].items()):
            print(
                f"    {agent:15s} commits={stats['commits']:4d}  "
                f"issues={stats['issues']:4d}  "
                f"TP={stats['true_positives']:3d}  "
                f"FP={stats['false_positives']:3d}  "
                f"more={stats['needs_more_data']:3d}",
                file=sys.stderr,
            )

    # Write JSON
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\nJSON written to: {args.output_json}", file=sys.stderr)

    # Write CSV
    write_csv(summary["findings"], args.output_csv)
    print(f"CSV written to:  {args.output_csv}", file=sys.stderr)


if __name__ == "__main__":
    main()
