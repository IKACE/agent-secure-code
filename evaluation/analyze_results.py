#!/usr/bin/env python3
"""
Step 4: Compute stats and comparison tables from evaluation results.

Reads all evaluation.json files from a results directory, computes reproduction
rates by vulnerability type, language, and original agent, and outputs summary
tables in multiple formats.

Usage:
    python analyze_results.py --results-dir results/qwen3-coder [--format table|json|csv]
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List


def load_evaluations(results_dir: Path) -> List[Dict[str, Any]]:
    """Load all evaluation.json files from results directory."""
    evaluations = []
    for eval_file in sorted(results_dir.rglob("evaluation.json")):
        try:
            data = json.loads(eval_file.read_text(encoding="utf-8"))
            evaluations.append(data)
        except (json.JSONDecodeError, OSError) as e:
            print(f"  [warn] Error reading {eval_file}: {e}", file=sys.stderr)
    return evaluations


def load_tasks_metadata(tasks_path: Path) -> Dict[str, Dict]:
    """Load tasks.jsonl for additional metadata (language, agents)."""
    metadata = {}
    if not tasks_path.exists():
        return metadata
    with open(tasks_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                task = json.loads(line)
                metadata[task["task_id"]] = task
            except (json.JSONDecodeError, KeyError):
                continue
    return metadata


def compute_stats(
    evaluations: List[Dict], tasks_meta: Dict[str, Dict]
) -> Dict[str, Any]:
    """Compute all statistics from evaluation results."""
    total = len(evaluations)
    if total == 0:
        return {"total": 0, "error": "No evaluations found"}

    # Overall assessment distribution
    assessment_counts = Counter(e["assessment"] for e in evaluations)

    # Reproduction rate: tasks where model reproduced the SAME vulnerability
    same_vuln = sum(1 for e in evaluations if e["assessment"] == "VULNERABLE_SAME")
    any_vuln = sum(1 for e in evaluations
                   if e["assessment"] in ("VULNERABLE_SAME", "VULNERABLE_DIFFERENT"))
    secure = sum(1 for e in evaluations
                 if e["assessment"] in ("SECURE", "SECURE_FP_ONLY"))

    # By vulnerability type
    by_vuln_type: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "reproduced": 0, "any_vuln": 0, "secure": 0})
    for e in evaluations:
        for vtype in e.get("original_vuln_types", []):
            by_vuln_type[vtype]["total"] += 1
            if e["assessment"] == "VULNERABLE_SAME":
                by_vuln_type[vtype]["reproduced"] += 1
            if e["assessment"] in ("VULNERABLE_SAME", "VULNERABLE_DIFFERENT"):
                by_vuln_type[vtype]["any_vuln"] += 1
            if e["assessment"] in ("SECURE", "SECURE_FP_ONLY"):
                by_vuln_type[vtype]["secure"] += 1

    # By language
    by_language: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "reproduced": 0, "any_vuln": 0, "secure": 0})
    for e in evaluations:
        task = tasks_meta.get(e["task_id"], {})
        lang = task.get("language", "unknown")
        by_language[lang]["total"] += 1
        if e["assessment"] == "VULNERABLE_SAME":
            by_language[lang]["reproduced"] += 1
        if e["assessment"] in ("VULNERABLE_SAME", "VULNERABLE_DIFFERENT"):
            by_language[lang]["any_vuln"] += 1
        if e["assessment"] in ("SECURE", "SECURE_FP_ONLY"):
            by_language[lang]["secure"] += 1

    # By original agent
    by_agent: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "reproduced": 0, "any_vuln": 0, "secure": 0})
    for e in evaluations:
        task = tasks_meta.get(e["task_id"], {})
        agents = task.get("agents", ["unknown"])
        for agent in agents:
            by_agent[agent]["total"] += 1
            if e["assessment"] == "VULNERABLE_SAME":
                by_agent[agent]["reproduced"] += 1
            if e["assessment"] in ("VULNERABLE_SAME", "VULNERABLE_DIFFERENT"):
                by_agent[agent]["any_vuln"] += 1
            if e["assessment"] in ("SECURE", "SECURE_FP_ONLY"):
                by_agent[agent]["secure"] += 1

    # Confusion matrix: original TP vs generated TP
    tp_pairs = []
    for e in evaluations:
        tp_pairs.append({
            "task_id": e["task_id"],
            "original_tp": e.get("original_tp", 0),
            "generated_tp": e.get("generated_tp", 0),
            "assessment": e["assessment"],
        })

    # Timing stats
    elapsed_list = [e.get("elapsed_seconds", 0) for e in evaluations if e.get("elapsed_seconds", 0) > 0]
    timing = {}
    if elapsed_list:
        timing = {
            "mean_seconds": round(sum(elapsed_list) / len(elapsed_list), 1),
            "min_seconds": round(min(elapsed_list), 1),
            "max_seconds": round(max(elapsed_list), 1),
            "total_seconds": round(sum(elapsed_list), 1),
        }

    model = evaluations[0].get("model", "unknown") if evaluations else "unknown"

    return {
        "model": model,
        "total_tasks": total,
        "overall": {
            "same_vuln": same_vuln,
            "same_vuln_rate": round(same_vuln / total * 100, 1),
            "any_vuln": any_vuln,
            "any_vuln_rate": round(any_vuln / total * 100, 1),
            "secure": secure,
            "secure_rate": round(secure / total * 100, 1),
        },
        "assessment_distribution": dict(assessment_counts.most_common()),
        "by_vuln_type": {k: dict(v) for k, v in sorted(by_vuln_type.items())},
        "by_language": {k: dict(v) for k, v in sorted(by_language.items())},
        "by_agent": {k: dict(v) for k, v in sorted(by_agent.items())},
        "tp_confusion": tp_pairs,
        "timing": timing,
    }


def format_table(stats: Dict[str, Any]) -> str:
    """Format stats as readable text tables."""
    lines = []
    model = stats.get("model", "?")
    total = stats.get("total_tasks", 0)
    overall = stats.get("overall", {})

    lines.append(f"{'='*70}")
    lines.append(f"  Vulnerability Reproduction Analysis — Model: {model}")
    lines.append(f"  Total tasks evaluated: {total}")
    lines.append(f"{'='*70}")

    # Overall
    lines.append(f"\n## Overall Results\n")
    lines.append(f"  Same vulnerability reproduced:  {overall.get('same_vuln',0):3d} / {total}  ({overall.get('same_vuln_rate',0):.1f}%)")
    lines.append(f"  Any vulnerability generated:    {overall.get('any_vuln',0):3d} / {total}  ({overall.get('any_vuln_rate',0):.1f}%)")
    lines.append(f"  Secure (no vulns):              {overall.get('secure',0):3d} / {total}  ({overall.get('secure_rate',0):.1f}%)")

    # Assessment distribution
    lines.append(f"\n## Assessment Distribution\n")
    for assessment, count in stats.get("assessment_distribution", {}).items():
        pct = count / max(total, 1) * 100
        bar = "#" * int(pct / 2)
        lines.append(f"  {assessment:25s}  {count:3d}  ({pct:5.1f}%)  {bar}")

    # By vulnerability type
    lines.append(f"\n## By Vulnerability Type\n")
    lines.append(f"  {'Type':40s} {'Total':>5s} {'Repro':>5s} {'Rate':>6s} {'Any':>5s} {'Secure':>6s}")
    lines.append(f"  {'-'*40} {'-'*5} {'-'*5} {'-'*6} {'-'*5} {'-'*6}")
    for vtype, data in sorted(stats.get("by_vuln_type", {}).items(),
                                key=lambda x: x[1].get("total", 0), reverse=True):
        t = data["total"]
        r = data.get("reproduced", 0)
        rate = f"{r/t*100:.0f}%" if t > 0 else "N/A"
        a = data.get("any_vuln", 0)
        s = data.get("secure", 0)
        lines.append(f"  {vtype:40s} {t:5d} {r:5d} {rate:>6s} {a:5d} {s:6d}")

    # By language
    lines.append(f"\n## By Language\n")
    lines.append(f"  {'Language':15s} {'Total':>5s} {'Repro':>5s} {'Rate':>6s} {'Secure':>6s}")
    lines.append(f"  {'-'*15} {'-'*5} {'-'*5} {'-'*6} {'-'*6}")
    for lang, data in sorted(stats.get("by_language", {}).items()):
        t = data["total"]
        r = data.get("reproduced", 0)
        rate = f"{r/t*100:.0f}%" if t > 0 else "N/A"
        s = data.get("secure", 0)
        lines.append(f"  {lang:15s} {t:5d} {r:5d} {rate:>6s} {s:6d}")

    # By agent
    lines.append(f"\n## By Original Agent\n")
    lines.append(f"  {'Agent':15s} {'Total':>5s} {'Repro':>5s} {'Rate':>6s} {'Secure':>6s}")
    lines.append(f"  {'-'*15} {'-'*5} {'-'*5} {'-'*6} {'-'*6}")
    for agent, data in sorted(stats.get("by_agent", {}).items()):
        t = data["total"]
        r = data.get("reproduced", 0)
        rate = f"{r/t*100:.0f}%" if t > 0 else "N/A"
        s = data.get("secure", 0)
        lines.append(f"  {agent:15s} {t:5d} {r:5d} {rate:>6s} {s:6d}")

    # Timing
    timing = stats.get("timing", {})
    if timing:
        lines.append(f"\n## Timing\n")
        lines.append(f"  Mean: {timing.get('mean_seconds',0):.1f}s  "
                     f"Min: {timing.get('min_seconds',0):.1f}s  "
                     f"Max: {timing.get('max_seconds',0):.1f}s  "
                     f"Total: {timing.get('total_seconds',0):.0f}s")

    lines.append("")
    return "\n".join(lines)


def format_markdown(stats: Dict[str, Any]) -> str:
    """Format stats as a markdown document."""
    lines = []
    model = stats.get("model", "?")
    total = stats.get("total_tasks", 0)
    overall = stats.get("overall", {})

    lines.append(f"# Vulnerability Reproduction Analysis — {model}\n")
    lines.append(f"**Total tasks evaluated:** {total}\n")

    # Overall
    lines.append(f"## Overall Results\n")
    lines.append(f"| Metric | Count | Rate |")
    lines.append(f"|--------|------:|-----:|")
    lines.append(f"| Same vuln reproduced | {overall.get('same_vuln',0)} | {overall.get('same_vuln_rate',0):.1f}% |")
    lines.append(f"| Any vuln generated | {overall.get('any_vuln',0)} | {overall.get('any_vuln_rate',0):.1f}% |")
    lines.append(f"| Secure | {overall.get('secure',0)} | {overall.get('secure_rate',0):.1f}% |")

    # Assessment distribution
    lines.append(f"\n## Assessment Distribution\n")
    lines.append(f"| Assessment | Count | Rate |")
    lines.append(f"|------------|------:|-----:|")
    for assessment, count in stats.get("assessment_distribution", {}).items():
        pct = count / max(total, 1) * 100
        lines.append(f"| {assessment} | {count} | {pct:.1f}% |")

    # By vulnerability type
    lines.append(f"\n## By Vulnerability Type\n")
    lines.append(f"| Type | Total | Reproduced | Rate | Any Vuln | Secure |")
    lines.append(f"|------|------:|-----------:|-----:|---------:|-------:|")
    for vtype, data in sorted(stats.get("by_vuln_type", {}).items(),
                                key=lambda x: x[1].get("total", 0), reverse=True):
        t = data["total"]
        r = data.get("reproduced", 0)
        rate = f"{r/t*100:.0f}%" if t > 0 else "N/A"
        a = data.get("any_vuln", 0)
        s = data.get("secure", 0)
        lines.append(f"| {vtype} | {t} | {r} | {rate} | {a} | {s} |")

    # By language
    lines.append(f"\n## By Language\n")
    lines.append(f"| Language | Total | Reproduced | Rate | Secure |")
    lines.append(f"|----------|------:|-----------:|-----:|-------:|")
    for lang, data in sorted(stats.get("by_language", {}).items()):
        t = data["total"]
        r = data.get("reproduced", 0)
        rate = f"{r/t*100:.0f}%" if t > 0 else "N/A"
        s = data.get("secure", 0)
        lines.append(f"| {lang} | {t} | {r} | {rate} | {s} |")

    # By agent
    lines.append(f"\n## By Original Agent\n")
    lines.append(f"| Agent | Total | Reproduced | Rate | Secure |")
    lines.append(f"|-------|------:|-----------:|-----:|-------:|")
    for agent, data in sorted(stats.get("by_agent", {}).items()):
        t = data["total"]
        r = data.get("reproduced", 0)
        rate = f"{r/t*100:.0f}%" if t > 0 else "N/A"
        s = data.get("secure", 0)
        lines.append(f"| {agent} | {t} | {r} | {rate} | {s} |")

    lines.append("")
    return "\n".join(lines)


def format_csv_output(stats: Dict[str, Any]) -> str:
    """Format per-task results as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "task_id", "model", "assessment", "matches_original_vuln",
        "original_tp", "generated_tp", "generated_fp",
        "original_vuln_types", "generated_vuln_types",
        "elapsed_seconds",
    ])
    for pair in stats.get("tp_confusion", []):
        # Find the full evaluation for this task
        task_id = pair["task_id"]
        writer.writerow([
            task_id,
            stats.get("model", ""),
            pair["assessment"],
            pair["assessment"] == "VULNERABLE_SAME",
            pair["original_tp"],
            pair["generated_tp"],
            "",  # generated_fp not in tp_pairs — would need full eval
            "",  # original_vuln_types
            "",  # generated_vuln_types
            "",  # elapsed
        ])
    return output.getvalue()


def main() -> None:
    ap = argparse.ArgumentParser(description="Analyze evaluation results")
    ap.add_argument("--results-dir", type=Path, required=True,
                     help="Directory containing evaluation results (e.g., results/qwen3-coder)")
    ap.add_argument("--tasks", type=Path,
                     default=Path(__file__).parent / "tasks.jsonl",
                     help="Path to tasks.jsonl for metadata")
    ap.add_argument("--format", type=str, default="table",
                     choices=["table", "json", "csv", "markdown"],
                     help="Output format")
    args = ap.parse_args()

    results_dir = args.results_dir.resolve()
    if not results_dir.exists():
        print(f"[error] Results directory not found: {results_dir}", file=sys.stderr)
        sys.exit(1)

    evaluations = load_evaluations(results_dir)
    print(f"Loaded {len(evaluations)} evaluations from {results_dir}", file=sys.stderr)

    if not evaluations:
        print("[error] No evaluation.json files found.", file=sys.stderr)
        sys.exit(1)

    tasks_meta = load_tasks_metadata(args.tasks)
    stats = compute_stats(evaluations, tasks_meta)

    # Output
    if args.format == "json":
        # Remove tp_confusion from JSON output (too verbose)
        stats_out = {k: v for k, v in stats.items() if k != "tp_confusion"}
        print(json.dumps(stats_out, indent=2, ensure_ascii=False))
    elif args.format == "csv":
        print(format_csv_output(stats))
    elif args.format == "markdown":
        print(format_markdown(stats))
    else:
        print(format_table(stats))

    # Write summary files
    summary_json = results_dir / "summary.json"
    stats_out = {k: v for k, v in stats.items() if k != "tp_confusion"}
    summary_json.write_text(
        json.dumps(stats_out, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    summary_md = results_dir / "summary.md"
    summary_md.write_text(format_markdown(stats), encoding="utf-8")

    print(f"\nWrote {summary_json} and {summary_md}", file=sys.stderr)


if __name__ == "__main__":
    main()
