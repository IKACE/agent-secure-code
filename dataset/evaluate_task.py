#!/usr/bin/env python3
"""
Unified task evaluator for the secure code generation dataset.

Runs three checks against any implementation file:
  1. Correctness tests  - Does the function behave correctly?
  2. Security exploit    - Can the vulnerability be exploited?
  3. Pattern matching    - Does regex-based vuln_check detect the vulnerability?

Usage:
  # Evaluate a specific implementation against a task:
  python evaluate_task.py <task_dir> <impl_file>

  # Evaluate the default standalone.js/py:
  python evaluate_task.py <task_dir>

  # Evaluate all tasks with their defaults:
  python evaluate_task.py --all

  # Compare insecure vs secure variants:
  python evaluate_task.py --all --compare

Examples:
  python evaluate_task.py data/tasks/BasedHardware__omi__.../ my_impl.js
  python evaluate_task.py --all --json > results.json
"""

import os
import sys
import json
import subprocess
import argparse
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
TASKS_DIR = SCRIPT_DIR / "data" / "tasks"


def run_cmd(cmd, cwd=None, timeout=60):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)


def detect_language(task_dir):
    """Detect if the task is Python or JavaScript."""
    if (task_dir / "standalone.py").exists():
        return "python"
    return "javascript"


def find_impl_file(task_dir, impl_arg=None):
    """Find the implementation file to evaluate."""
    if impl_arg:
        p = Path(impl_arg)
        if not p.is_absolute():
            p = Path.cwd() / p
        return p
    lang = detect_language(task_dir)
    return task_dir / ("standalone.py" if lang == "python" else "standalone.js")


def run_correctness_test(task_dir, impl_file):
    """Run correctness tests. Returns (passed, total, details)."""
    lang = detect_language(task_dir)
    tests_dir = task_dir / "tests"

    if lang == "python":
        test_file = tests_dir / "test_correctness.py"
        if not test_file.exists():
            return None, None, "No test_correctness.py found"
        cmd = [sys.executable, "-m", "pytest", str(test_file), str(impl_file),
               "-v", "--tb=short"]
        rc, stdout, stderr = run_cmd(cmd, cwd=str(task_dir), timeout=120)
        output = stdout + "\n" + stderr
        passed = output.count(" PASSED")
        failed = output.count(" FAILED")
        return passed, passed + failed, output
    else:
        test_file = tests_dir / "test_correctness.js"
        if not test_file.exists():
            return None, None, "No test_correctness.js found"
        cmd = ["node", str(test_file), str(impl_file)]
        rc, stdout, stderr = run_cmd(cmd, cwd=str(task_dir), timeout=30)
        output = stdout + "\n" + stderr
        passed = output.count(": PASS")
        failed = output.count(": FAIL")
        errors = 1 if rc != 0 and passed == 0 else 0
        total = passed + failed + errors
        return passed, total if total > 0 else None, output


def run_security_test(task_dir, impl_file):
    """Run security exploit test. Returns ('VULNERABLE'|'SAFE'|'ERROR', details)."""
    lang = detect_language(task_dir)
    tests_dir = task_dir / "tests"

    if lang == "python":
        test_file = tests_dir / "test_security.py"
        if not test_file.exists():
            return "SKIP", "No test_security.py found"
        cmd = [sys.executable, str(test_file), str(impl_file)]
    else:
        test_file = tests_dir / "test_security.js"
        if not test_file.exists():
            return "SKIP", "No test_security.js found"
        cmd = ["node", str(test_file), str(impl_file)]

    rc, stdout, stderr = run_cmd(cmd, cwd=str(task_dir), timeout=30)
    output = (stdout + "\n" + stderr).strip()

    if "VULNERABLE" in output:
        return "VULNERABLE", output
    elif "SAFE" in output:
        return "SAFE", output
    else:
        return "ERROR", output


def run_vuln_check(task_dir, impl_file):
    """Run regex-based vulnerability pattern checker. Returns ('VULN'|'SAFE'|'ERROR', details)."""
    vuln_check = SCRIPT_DIR / "vuln_check.py"
    if not vuln_check.exists():
        return "SKIP", "vuln_check.py not found"

    task_json = task_dir / "task.json"
    if not task_json.exists():
        return "SKIP", "task.json not found"

    with open(task_json) as f:
        task = json.load(f)

    cmd = [sys.executable, str(vuln_check), "--task-dir", str(task_dir),
           "--code-file", str(impl_file)]
    rc, stdout, stderr = run_cmd(cmd, timeout=10)
    output = (stdout + "\n" + stderr).strip()

    try:
        result = json.loads(stdout)
        if result.get("vulnerable") is True:
            return "VULN", output
        elif result.get("vulnerable") is False:
            return "SAFE", output
        else:
            return "UNKNOWN", output
    except (json.JSONDecodeError, KeyError):
        return "ERROR", output


def evaluate_task(task_dir, impl_file):
    """Run all evaluations for a single task. Returns results dict."""
    task_dir = Path(task_dir)
    impl_file = Path(impl_file)

    task_json = task_dir / "task.json"
    meta = {}
    if task_json.exists():
        with open(task_json) as f:
            meta = json.load(f)

    results = {
        "task": task_dir.name,
        "impl": str(impl_file.name),
        "cwe": meta.get("cwe", "unknown"),
        "vuln_type": meta.get("vuln_type", "unknown"),
    }

    passed, total, _ = run_correctness_test(task_dir, impl_file)
    results["correctness_passed"] = passed
    results["correctness_total"] = total
    results["correctness_ok"] = passed == total if total else None

    sec_result, _ = run_security_test(task_dir, impl_file)
    results["security_exploit"] = sec_result

    vuln_result, _ = run_vuln_check(task_dir, impl_file)
    results["vuln_pattern"] = vuln_result

    return results


def print_results(results_list):
    """Pretty-print evaluation results."""
    print("\n" + "=" * 90)
    print(f"{'Task':<55} {'Correct':>8} {'Exploit':>12} {'Pattern':>10}")
    print("=" * 90)

    for r in results_list:
        short_name = r["task"][:53]
        correct = f"{r['correctness_passed']}/{r['correctness_total']}" if r["correctness_total"] else "N/A"
        exploit = r["security_exploit"]
        pattern = r["vuln_pattern"]
        print(f"{short_name:<55} {correct:>8} {exploit:>12} {pattern:>10}")

    print("=" * 90)

    total = len(results_list)
    correct_ok = sum(1 for r in results_list if r.get("correctness_ok"))
    vuln = sum(1 for r in results_list if r["security_exploit"] == "VULNERABLE")
    safe = sum(1 for r in results_list if r["security_exploit"] == "SAFE")
    print(f"\nSummary: {total} tasks evaluated")
    print(f"  Correctness: {correct_ok}/{total} all tests passing")
    print(f"  Security: {vuln} VULNERABLE, {safe} SAFE")


def main():
    parser = argparse.ArgumentParser(description="Evaluate secure code generation tasks")
    parser.add_argument("task_dir", nargs="?", help="Path to task directory")
    parser.add_argument("impl_file", nargs="?", help="Path to implementation file")
    parser.add_argument("--all", action="store_true", help="Evaluate all tasks")
    parser.add_argument("--compare", action="store_true",
                        help="Compare insecure vs secure variants")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.all:
        results = []
        for task_dir in sorted(TASKS_DIR.iterdir()):
            if not task_dir.is_dir():
                continue
            impl = find_impl_file(task_dir)
            if not impl.exists():
                continue
            print(f"  Evaluating: {task_dir.name[:60]}...", file=sys.stderr)
            r = evaluate_task(task_dir, impl)
            results.append(r)

        if args.compare:
            secure_results = []
            for task_dir in sorted(TASKS_DIR.iterdir()):
                if not task_dir.is_dir():
                    continue
                lang = detect_language(task_dir)
                ext = "py" if lang == "python" else "js"
                secure = task_dir / f"standalone_secure.{ext}"
                if not secure.exists():
                    continue
                print(f"  Evaluating secure: {task_dir.name[:55]}...", file=sys.stderr)
                r = evaluate_task(task_dir, secure)
                r["variant"] = "secure"
                secure_results.append(r)

            if args.json:
                print(json.dumps({"insecure": results, "secure": secure_results}, indent=2))
            else:
                print("\n### INSECURE VARIANTS ###")
                print_results(results)
                print("\n### SECURE VARIANTS ###")
                print_results(secure_results)
        else:
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print_results(results)

    elif args.task_dir:
        task_dir = Path(args.task_dir)
        if not task_dir.is_absolute():
            task_dir = Path.cwd() / task_dir
        impl = find_impl_file(task_dir, args.impl_file)

        if not impl.exists():
            print(f"ERROR: Implementation file not found: {impl}", file=sys.stderr)
            sys.exit(1)

        r = evaluate_task(task_dir, impl)
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            print_results([r])
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
