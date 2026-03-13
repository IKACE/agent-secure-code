#!/usr/bin/env python3
"""
Run the full evaluation demo on all tasks × 3 variants.

For each task:
  1. Load the 3 variants (insecure, secure, broken)
  2. Splice each into the original file
  3. Run unit tests on each spliced file
  4. Run vulnerability pattern checks on each variant
  5. Print a summary table

Usage:
    python run_demo.py [--tasks-dir data/tasks]
    python run_demo.py --tasks-dir data/tasks --skip-tests  # Skip unit tests
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from evaluate_task import splice_code, load_task
from vuln_check import check_vulnerability


# ---------------------------------------------------------------------------
# Test runner (adapted from evaluate_task.py but more robust)
# ---------------------------------------------------------------------------

def run_tests_on_spliced(task_dir: Path, spliced_file: Path, task: Dict) -> Dict:
    """Run unit tests and return {passed, total, output, error}."""
    tests_dir = task_dir / "tests"
    test_files = sorted(tests_dir.glob("test_*"))
    if not test_files:
        return {"passed": 0, "total": 0, "output": "", "error": "no tests"}

    lang = task.get("language", "javascript")
    results = {"passed": 0, "total": 0, "output": "", "error": None}

    for test_file in test_files:
        if lang == "python":
            cmd = ["python3", "-m", "pytest", str(test_file), "-v", "--tb=short", "-x"]
        else:
            cmd = ["node", "--experimental-vm-modules", str(test_file)]

        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(task_dir),
                env={**os.environ, "SPLICED_FILE": str(spliced_file)},
            )
            results["output"] += r.stdout + r.stderr
            results["total"] += 1
            if r.returncode == 0:
                results["passed"] += 1
        except subprocess.TimeoutExpired:
            results["output"] += f"\nTimeout: {test_file.name}"
            results["total"] += 1
            results["error"] = "timeout"
        except FileNotFoundError as e:
            results["error"] = str(e)

    return results


# ---------------------------------------------------------------------------
# Evaluate one variant
# ---------------------------------------------------------------------------

def evaluate_variant(
    task_dir: Path,
    task: Dict,
    variant_name: str,
    variant_code: str,
    ext: str,
    original_content: str,
    mask_region: List[int],
    skip_tests: bool = False,
) -> Dict:
    """Evaluate a single variant: splice, test, vuln-check."""
    # Splice into original
    spliced = splice_code(original_content, variant_code,
                          mask_region[0], mask_region[1])

    # Write spliced file
    eval_dir = task_dir / "evaluate"
    eval_dir.mkdir(exist_ok=True)
    spliced_file = eval_dir / f"spliced_{variant_name}.{ext}"
    spliced_file.write_text(spliced, encoding="utf-8")

    result = {
        "variant": variant_name,
        "spliced_file": str(spliced_file),
    }

    # Run tests
    if not skip_tests:
        test_result = run_tests_on_spliced(task_dir, spliced_file, task)
        result["tests_passed"] = test_result["passed"]
        result["tests_total"] = test_result["total"]
        result["tests_error"] = test_result.get("error")
    else:
        result["tests_passed"] = "?"
        result["tests_total"] = "?"

    # Vulnerability check (on the variant code, not the full spliced file)
    vuln_result = check_vulnerability(variant_code, task)
    result["vulnerable"] = vuln_result["vulnerable"]
    result["vuln_findings"] = vuln_result["findings"]

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Run evaluation demo")
    ap.add_argument("--tasks-dir", type=Path,
                    default=Path(__file__).parent / "data" / "tasks")
    ap.add_argument("--tasks-jsonl", type=Path,
                    default=Path(__file__).parent / "data" / "tasks_function_level.jsonl")
    ap.add_argument("--skip-tests", action="store_true",
                    help="Skip unit tests (just do vuln checks)")
    ap.add_argument("--output", type=Path,
                    help="Save detailed results to JSON file")
    args = ap.parse_args()

    # Load full task metadata from JSONL
    tasks_by_id = {}
    if args.tasks_jsonl.exists():
        with open(args.tasks_jsonl, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    task = json.loads(line)
                    tasks_by_id[task["task_id"]] = task

    task_dirs = sorted(d for d in args.tasks_dir.iterdir() if d.is_dir())
    print(f"\n{'='*80}")
    print(f"  Evaluation Demo: {len(task_dirs)} tasks x 3 variants")
    print(f"{'='*80}\n")

    all_results = []
    summary_rows = []

    for i, task_dir in enumerate(task_dirs, 1):
        task_id = task_dir.name
        short_id = task_id[:60]

        # Load task metadata
        task = tasks_by_id.get(task_id)
        if not task:
            task_json = task_dir / "task.json"
            if task_json.exists():
                task = json.loads(task_json.read_text(encoding="utf-8"))
            else:
                print(f"  [{i}] SKIP {short_id} (no metadata)")
                continue

        # Find extension
        ext = "txt"
        for e in ("ts", "tsx", "js", "jsx", "mjs", "py", "html"):
            if (task_dir / f"full_file_original.{e}").exists():
                ext = e
                break

        # Read original file
        orig_file = task_dir / f"full_file_original.{ext}"
        if not orig_file.exists():
            print(f"  [{i}] SKIP {short_id} (no original file)")
            continue
        original_content = orig_file.read_text(encoding="utf-8")

        mask_region = task.get("mask_region", task.get("vuln_lines", [1, 1]))

        # Load variants
        variants_dir = task_dir / "variants"
        if not variants_dir.exists():
            print(f"  [{i}] SKIP {short_id} (no variants)")
            continue

        vuln_type = task.get("vuln_type", "?")[:30]
        cwe = task.get("cwe", "?")
        print(f"  [{i}/{len(task_dirs)}] {vuln_type} ({cwe})")
        print(f"           {short_id}")

        task_results = {"task_id": task_id, "vuln_type": vuln_type, "cwe": cwe, "variants": {}}
        row = {"task": short_id[:40], "vuln": vuln_type[:25], "cwe": cwe}

        for variant_name in ("insecure", "secure", "broken"):
            # Find variant file
            variant_file = None
            for e in (ext, "ts", "tsx", "js", "jsx", "mjs", "py", "html"):
                candidate = variants_dir / f"{variant_name}.{e}"
                if candidate.exists():
                    variant_file = candidate
                    break

            if variant_file is None:
                print(f"           {variant_name:10s}: MISSING")
                row[f"{variant_name}_tests"] = "N/A"
                row[f"{variant_name}_vuln"] = "N/A"
                continue

            variant_code = variant_file.read_text(encoding="utf-8")

            result = evaluate_variant(
                task_dir, task, variant_name, variant_code, ext,
                original_content, mask_region, skip_tests=args.skip_tests,
            )

            tp = result.get("tests_passed", "?")
            tt = result.get("tests_total", "?")
            vuln = result.get("vulnerable")
            vuln_str = "VULN" if vuln else ("SAFE" if vuln is False else "N/A")
            n_findings = len(result.get("vuln_findings", []))

            print(f"           {variant_name:10s}: tests={tp}/{tt}  vuln={vuln_str} ({n_findings} findings)")

            task_results["variants"][variant_name] = result
            row[f"{variant_name}_tests"] = f"{tp}/{tt}"
            row[f"{variant_name}_vuln"] = vuln_str

        all_results.append(task_results)
        summary_rows.append(row)
        print()

    # Print summary table
    print(f"\n{'='*120}")
    print(f"  SUMMARY TABLE")
    print(f"{'='*120}")
    print()

    # Header
    hdr = f"{'#':>3}  {'Vulnerability':25s}  {'CWE':10s}  "
    hdr += f"{'Insecure':>12s}  {'Secure':>12s}  {'Broken':>12s}  "
    hdr += f"{'Ins.Vuln':>8s}  {'Sec.Vuln':>8s}  {'Brk.Vuln':>8s}"
    print(hdr)
    print("-" * 120)

    expected_correct = 0
    total_checks = 0

    for i, row in enumerate(summary_rows, 1):
        line = f"{i:3d}  {row.get('vuln', '?'):25s}  {row.get('cwe', '?'):10s}  "
        line += f"{row.get('insecure_tests', 'N/A'):>12s}  "
        line += f"{row.get('secure_tests', 'N/A'):>12s}  "
        line += f"{row.get('broken_tests', 'N/A'):>12s}  "
        line += f"{row.get('insecure_vuln', 'N/A'):>8s}  "
        line += f"{row.get('secure_vuln', 'N/A'):>8s}  "
        line += f"{row.get('broken_vuln', 'N/A'):>8s}"
        print(line)

        # Check expected outcomes
        # insecure should be VULN, secure should be SAFE
        if row.get("insecure_vuln") == "VULN":
            expected_correct += 1
        total_checks += 1
        if row.get("secure_vuln") == "SAFE":
            expected_correct += 1
        total_checks += 1

    print("-" * 120)
    print(f"\n  Vulnerability detection accuracy: {expected_correct}/{total_checks} "
          f"({100*expected_correct/total_checks:.0f}% correct)\n")

    print("  Expected pattern:")
    print("    - Insecure: tests PASS, vuln = VULN  (original vulnerable code)")
    print("    - Secure:   tests PASS, vuln = SAFE  (fixed code)")
    print("    - Broken:   tests FAIL, vuln = varies (functionally broken)")
    print()

    # Save detailed results
    out = args.output or (args.tasks_dir.parent / "demo_results.json")
    out.write_text(json.dumps(all_results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Detailed results saved to: {out}\n")


if __name__ == "__main__":
    main()
