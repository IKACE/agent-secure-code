import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Tuple


def walk_report_paths_and_collect_errors(
    report_root: str,
    error_paths_out: List[str],
) -> Iterable[str]:
    """
    Single os.walk: yield each codeql_report.json path as it is found (so
    aggregation can start immediately) and append each error.json path to
    error_paths_out. Avoids blocking on a full tree walk before any progress.
    """
    for dirpath, _, filenames in os.walk(report_root):
        if "codeql_report.json" in filenames:
            yield os.path.join(dirpath, "codeql_report.json")
        if "error.json" in filenames:
            error_paths_out.append(os.path.join(dirpath, "error.json"))


def load_report(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_findings(report_path: str, report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flatten `ai_introduced_findings` from a single `codeql_report.json`
    into a list of normalized vulnerability records.
    """
    repo = report.get("repo")
    sha = report.get("sha")
    parent_sha = report.get("parent_sha")
    html_url = report.get("html_url")

    findings = report.get("ai_introduced_findings") or []
    normalized: List[Dict[str, Any]] = []

    for f in findings:
        normalized.append(
            {
                "repo": repo,
                "sha": sha,
                "parent_sha": parent_sha,
                "html_url": html_url,
                "file": f.get("file"),
                "line": f.get("line"),
                "rule_id": f.get("ruleId"),
                "message": f.get("message"),
                "security_severity": f.get("security_severity"),
                "severity_level": f.get("severity_level"),
                "report_path": report_path,
            }
        )

    return normalized


def aggregate_reports(
    report_paths_iter: Iterable[str],
    progress_interval: int = 500,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Load each `codeql_report.json` from the iterator and return (findings, num_reports).
    Yields report paths as the walk progresses so loading starts immediately.
    Prints progress to stderr every progress_interval reports.
    """
    all_findings: List[Dict[str, Any]] = []
    num_reports = 0

    for report_path in report_paths_iter:
        num_reports += 1
        if progress_interval and num_reports % progress_interval == 0:
            print(f"[progress] {num_reports} reports processed", file=sys.stderr)

        try:
            report = load_report(report_path)
        except Exception:
            continue

        findings = extract_findings(report_path, report)
        all_findings.extend(findings)

    return all_findings, num_reports


def build_summary_by_repo_and_rule(
    findings: Iterable[Dict[str, Any]]
) -> Dict[str, Dict[str, int]]:
    """
    Build a nested summary:

    {
        "owner/repo": {
            "rule_id": count,
            ...
        },
        ...
    }
    """
    summary: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for f in findings:
        repo = f.get("repo") or ""
        rule_id = f.get("rule_id") or ""
        if not repo or not rule_id:
            continue
        summary[repo][rule_id] += 1

    # Convert nested defaultdicts to plain dicts
    return {repo: dict(rules) for repo, rules in summary.items()}


def build_vulnerabilities_by_occurrence(
    findings: Iterable[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Build a list of (rule_id, count) sorted by count descending, for quick
    lookup of most common vulnerability types.
    """
    counts: Dict[str, int] = defaultdict(int)
    for f in findings:
        rule_id = f.get("rule_id") or ""
        if rule_id:
            counts[rule_id] += 1
    return [
        {"rule_id": rule_id, "count": count}
        for rule_id, count in sorted(counts.items(), key=lambda x: -x[1])
    ]


def build_vulnerabilities_by_severity(
    findings: Iterable[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Build a list of (severity_level, count) sorted by severity from high to low.
    Uses CodeQL/GitHub code scanning convention ordering.
    """
    order = ["critical", "high", "medium", "low", "unknown"]
    counts: Dict[str, int] = defaultdict(int)
    for f in findings:
        level = (f.get("severity_level") or "unknown").lower()
        if level not in order:
            level = "unknown"
        counts[level] += 1
    return [{"severity_level": level, "count": counts.get(level, 0)} for level in order]


def write_json_output(
    out_path: str,
    findings: List[Dict[str, Any]],
    num_analyzed_commits: int,
    num_error_commits: int,
) -> None:
    """
    Write a JSON file containing both the flat findings list and a
    per-repo/per-rule summary.
    """
    summary = build_summary_by_repo_and_rule(findings)
    vulnerabilities_by_occurrence = build_vulnerabilities_by_occurrence(findings)
    vulnerabilities_by_severity = build_vulnerabilities_by_severity(findings)
    stats = {
        "num_analyzed_commits": num_analyzed_commits,
        "num_error_commits": num_error_commits,
        "num_attempted_commits": num_analyzed_commits + num_error_commits,
    }
    payload = {
        "total_findings": len(findings),
        "findings": findings,
        "summary_by_repo_and_rule": summary,
        "vulnerabilities_by_occurrence": vulnerabilities_by_occurrence,
        "stats": stats,
        "vulnerabilities_by_severity": vulnerabilities_by_severity,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def write_csv_output(out_path: str, findings: List[Dict[str, Any]]) -> None:
    """
    Write a CSV file with one row per AI-introduced finding.
    """
    fieldnames = [
        "repo",
        "sha",
        "parent_sha",
        "file",
        "line",
        "rule_id",
        "message",
        "security_severity",
        "severity_level",
        "html_url",
        "report_path",
    ]

    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in findings:
            writer.writerow({k: row.get(k) for k in fieldnames})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate CodeQL AI-introduced vulnerabilities from "
            "codeql_report.json files into JSON and CSV."
        )
    )
    parser.add_argument(
        "--report-root",
        required=False,
        default=os.environ.get(
            "PATCH_ANALYSIS_REPORT_DIR", "/mnt/storage/yilegu/patch_analysis/output"
        ),
        help=(
            "Root directory containing {owner__repo}/{sha}/codeql_report.json "
            "(default: env PATCH_ANALYSIS_REPORT_DIR or "
            "/mnt/storage/yilegu/patch_analysis/output)."
        ),
    )
    parser.add_argument(
        "--out-json",
        required=False,
        default="aggregated_codeql_findings.json",
        help="Path for aggregated JSON output (default: aggregated_codeql_findings.json).",
    )
    parser.add_argument(
        "--out-csv",
        required=False,
        default="aggregated_codeql_findings.csv",
        help="Path for aggregated CSV output (default: aggregated_codeql_findings.csv).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    error_paths: List[str] = []
    report_path_iter = walk_report_paths_and_collect_errors(
        args.report_root,
        error_paths,
    )
    print("Walking report root and aggregating (progress below)...", file=sys.stderr)
    findings, num_analyzed = aggregate_reports(report_path_iter, progress_interval=500)
    num_errors = len(error_paths)
    print(f"Done: {num_analyzed} reports, {num_errors} errors.", file=sys.stderr)

    write_json_output(args.out_json, findings, num_analyzed, num_errors)
    write_csv_output(args.out_csv, findings)


if __name__ == "__main__":
    main()
