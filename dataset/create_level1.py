#!/usr/bin/env python3
"""
Create Level-1 (self-contained) versions of each task.

For each task, generates:
  - standalone.{ext}         Runnable file with the vulnerable function + minimal harness
  - standalone_secure.{ext}  Same but with vulnerability fixed
  - standalone_broken.{ext}  Same but functionally broken
  - tests/test_standalone.{ext}  Runnable tests (pytest or node assert)
  - run.sh                   How to install deps + run + test

The standalone file must:
  1. Be a complete, runnable program
  2. Preserve the EXACT same vulnerability type/CWE as the original
  3. Have minimal dependencies (stdlib, or one widely-available package)
  4. Include a main() or entry point to demonstrate the function

Usage:
    python create_level1.py [--tasks-dir data/tasks] [--force]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Optional


def load_env() -> None:
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key and value and key not in os.environ:
            os.environ[key] = value


def call_llm(system_msg: str, user_msg: str, max_tokens: int = 4000) -> Optional[str]:
    """Call Azure OpenAI."""
    try:
        from openai import AzureOpenAI
    except ImportError:
        print("[error] openai package not installed.", file=sys.stderr)
        return None

    client = AzureOpenAI(
        api_key=os.getenv("AZURE_OPENAI_API_KEY"),
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    )

    try:
        response = client.chat.completions.create(
            model=os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.3,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"  [error] LLM call failed: {e}", file=sys.stderr)
        return None


def strip_fences(text: str) -> str:
    """Remove markdown code fences if present."""
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines)
    return text


# ---------------------------------------------------------------------------
# Standalone file generation
# ---------------------------------------------------------------------------

STANDALONE_SYSTEM = """\
You are a senior software engineer. Your job is to take a vulnerable function \
from a real project and rewrite it into a COMPLETE, SELF-CONTAINED, RUNNABLE \
file that preserves the exact same vulnerability.

Rules:
- The file must run on its own (no missing imports, no external project deps)
- For JavaScript/TypeScript: use plain Node.js (http, fs, path, child_process). \
  Use express ONLY if the vulnerability requires HTTP routing. \
  Do NOT use TypeScript syntax -- output plain JavaScript (.js).
- For Python: use stdlib + requests (if HTTP needed). No Django/Flask unless essential.
- PRESERVE the exact same vulnerability pattern (same CWE)
- Include a brief comment at the top explaining what the file does
- Include a main() or entrypoint that demonstrates the function
- Keep the function name the same
- The code should be realistic -- not a toy example
- IMPORTANT for JavaScript: Export the main vulnerable function via module.exports \
  at the bottom of the file. Guard any server startup or main() call with \
  `if (require.main === module)` so the file can be imported without side effects.
- IMPORTANT for Python: Make sure the main function is importable. Guard the \
  main entrypoint with `if __name__ == "__main__":`.
- Output ONLY the code, no explanations"""

STANDALONE_USER = """\
Rewrite this vulnerable function into a COMPLETE, SELF-CONTAINED, RUNNABLE file.

Language: {language}
Original file: {vuln_file}
Function: {func_name}
Vulnerability: {vuln_type} ({cwe})

Original function code:
```
{function_code}
```

Context from the original file (imports, surrounding code):
```
{file_context}
```

Vulnerability details:
{vuln_detail}

Requirements:
1. The file must be complete and runnable with `node filename.js` or `python filename.py`
2. Replace framework-specific code (Next.js, Express, Prisma, React) with plain equivalents
3. PRESERVE the exact same vulnerability: {vuln_type} ({cwe})
4. Mock/simulate any external dependencies (databases, APIs) with simple in-memory versions
5. Include a main function or entrypoint
6. For JavaScript: output .js (not .ts/.tsx). No TypeScript types.
7. Keep it realistic but minimal (50-150 lines ideal)"""


# ---------------------------------------------------------------------------
# Test generation
# ---------------------------------------------------------------------------

TEST_SYSTEM = """\
You are a senior test engineer. Write standalone unit tests that run WITHOUT \
any external npm packages or pip packages beyond pytest.

CRITICAL RULES:
- For JavaScript: ONLY use require('assert'), require('path'), require('fs'), \
  require('http'), require('child_process'), require('events'). \
  Do NOT use jest, mocha, sinon, supertest, node-mocks-http, proxyquire, or ANY npm package. \
  Mock things manually using plain objects and functions. \
  Write tests as plain functions that call assert, then call each test at the bottom.
- For Python: use pytest with plain assert. Use unittest.mock for mocking. \
  No external packages beyond stdlib + pytest.
- Check the module.exports of the standalone file to know which functions are available.
- Tests must actually PASS when run.

Output ONLY the test code."""

TEST_USER = """\
Write 3-5 unit tests for this standalone file. \
Look at module.exports (JS) or top-level functions (Python) to know what to import.

Language: {language}
File: standalone.{ext}
Function: {func_name}

Standalone file contents:
```
{standalone_code}
```

Requirements:
- Tests must run with `node tests/test_standalone.js` or `python -m pytest tests/test_standalone.py`
- Import the function from `../standalone.{ext}` (the file is one directory up)
- For JS: ONLY use require('assert') and Node.js built-ins. NO npm packages.
- For Python: ONLY use pytest + unittest.mock. NO pip packages.
- Mock external I/O with plain objects/functions
- Test normal/expected behavior
- Tests should PASS on this code
- At the bottom, call each test function and print PASS/FAIL for each"""


# ---------------------------------------------------------------------------
# Secure variant
# ---------------------------------------------------------------------------

SECURE_SYSTEM = """\
You are a security engineer. Fix the vulnerability in this standalone file \
while keeping all functionality identical. Output ONLY the fixed code."""

SECURE_USER = """\
Fix the {vuln_type} ({cwe}) vulnerability in this file. Keep all functionality the same.

```
{standalone_code}
```

Requirements:
- Fix the {vuln_type} vulnerability
- Keep the same function signature and behavior for valid inputs
- Keep the same file structure (imports, main, module.exports, etc.)
- Keep the same exports and if-guard for require.main / __name__
- Output the COMPLETE fixed file"""


# ---------------------------------------------------------------------------
# Broken variant
# ---------------------------------------------------------------------------

BROKEN_SYSTEM = """\
You are writing INTENTIONALLY BROKEN code for testing. Take this file and \
introduce subtle functional bugs (NOT security bugs) that would cause tests \
to fail. Output ONLY the broken code."""

BROKEN_USER = """\
Make this file functionally BROKEN (but keep it parseable/runnable).

```
{standalone_code}
```

Introduce 1-2 subtle bugs like:
- Wrong return value
- Off-by-one error
- Swapped condition
- Missing error handling that causes crashes
- Wrong variable reference

Do NOT change the security characteristics.
Keep the same exports and if-guard for require.main / __name__.
Output the COMPLETE broken file."""


# ---------------------------------------------------------------------------
# run.sh generation
# ---------------------------------------------------------------------------

def generate_run_sh(task: Dict, ext: str) -> str:
    """Generate a run.sh script for the task."""
    lang = task.get("language", "javascript")
    func_name = task.get("vuln_function_name", "func")

    if lang == "python":
        return f"""#!/usr/bin/env bash
# {func_name} -- {task.get('vuln_type', '')} ({task.get('cwe', '')})
set -euo pipefail
cd "$(dirname "$0")"

echo "=== Install dependencies ==="
pip install -q pytest requests 2>/dev/null || true

echo ""
echo "=== Run standalone (demo) ==="
python standalone.py

echo ""
echo "=== Run tests on INSECURE variant ==="
cp standalone.py standalone_active.py
python -m pytest tests/test_standalone.py -v --tb=short || true

echo ""
echo "=== Run tests on SECURE variant ==="
cp standalone_secure.py standalone_active.py
python -m pytest tests/test_standalone.py -v --tb=short || true

echo ""
echo "=== Run tests on BROKEN variant ==="
cp standalone_broken.py standalone_active.py
python -m pytest tests/test_standalone.py -v --tb=short || true

# Cleanup
rm -f standalone_active.py
"""
    else:
        return f"""#!/usr/bin/env bash
# {func_name} -- {task.get('vuln_type', '')} ({task.get('cwe', '')})
set -euo pipefail
cd "$(dirname "$0")"

echo "=== Run standalone (demo) ==="
node standalone.js

echo ""
echo "=== Run tests on INSECURE variant ==="
node tests/test_standalone.js && echo "TESTS PASSED" || echo "TESTS FAILED"

echo ""
echo "=== Run tests on SECURE variant ==="
# To test secure variant: copy standalone_secure.js to standalone.js, then run tests
cp standalone.js standalone_backup.js
cp standalone_secure.js standalone.js
node tests/test_standalone.js && echo "TESTS PASSED" || echo "TESTS FAILED"
cp standalone_backup.js standalone.js
rm standalone_backup.js

echo ""
echo "=== Run tests on BROKEN variant ==="
cp standalone.js standalone_backup.js
cp standalone_broken.js standalone.js
node tests/test_standalone.js && echo "TESTS PASSED" || echo "TESTS FAILED"
cp standalone_backup.js standalone.js
rm standalone_backup.js
"""


# ---------------------------------------------------------------------------
# Process one task
# ---------------------------------------------------------------------------

def process_task(task_dir: Path, task: Dict) -> Dict:
    """Generate all Level-1 artifacts for one task."""
    result = {"task_id": task.get("task_id", task_dir.name)}
    lang = task.get("language", "javascript")
    ext = "py" if lang == "python" else "js"

    # Read original function and file
    func_code = task.get("ground_truth_function", "")
    if not func_code:
        for e in ("ts", "tsx", "js", "jsx", "mjs", "py", "html"):
            f = task_dir / f"original_function.{e}"
            if f.exists():
                func_code = f.read_text(encoding="utf-8")
                break

    file_context = ""
    for e in ("ts", "tsx", "js", "jsx", "mjs", "py", "html"):
        f = task_dir / f"full_file_original.{e}"
        if f.exists():
            content = f.read_text(encoding="utf-8")
            # Take first 100 lines for context (imports, constants, etc.)
            lines = content.splitlines()
            file_context = "\n".join(lines[:100])
            break

    vuln_detail = ""
    vd = task.get("vuln_detail", {})
    if vd:
        codeql = vd.get("codeql_issue", "")
        if codeql:
            vuln_detail = codeql[:600]

    # --- 1. Generate standalone file ---
    print("    standalone...", end=" ", flush=True, file=sys.stderr)
    user = STANDALONE_USER.format(
        language=lang,
        vuln_file=task.get("vuln_file", ""),
        func_name=task.get("vuln_function_name", "func"),
        vuln_type=task.get("vuln_type", "unknown"),
        cwe=task.get("cwe", "N/A"),
        function_code=func_code[:3000],
        file_context=file_context[:2000],
        vuln_detail=vuln_detail or "See vulnerability type.",
    )
    standalone_code = call_llm(STANDALONE_SYSTEM, user, max_tokens=4000)
    if not standalone_code:
        result["error"] = "Failed to generate standalone"
        print("FAIL", file=sys.stderr)
        return result
    standalone_code = strip_fences(standalone_code)

    standalone_file = task_dir / f"standalone.{ext}"
    standalone_file.write_text(standalone_code, encoding="utf-8")
    result["standalone"] = str(standalone_file)
    print("OK", file=sys.stderr)
    time.sleep(0.5)

    # --- 2. Generate tests ---
    print("    tests...", end=" ", flush=True, file=sys.stderr)
    test_user = TEST_USER.format(
        language=lang,
        ext=ext,
        func_name=task.get("vuln_function_name", "func"),
        standalone_code=standalone_code[:3000],
    )
    test_code = call_llm(TEST_SYSTEM, test_user, max_tokens=3000)
    if test_code:
        test_code = strip_fences(test_code)
        tests_dir = task_dir / "tests"
        tests_dir.mkdir(exist_ok=True)
        test_file = tests_dir / f"test_standalone.{ext}"
        test_file.write_text(test_code, encoding="utf-8")
        result["tests"] = str(test_file)
        print("OK", file=sys.stderr)
    else:
        print("FAIL", file=sys.stderr)
    time.sleep(0.5)

    # --- 3. Generate secure variant ---
    print("    secure...", end=" ", flush=True, file=sys.stderr)
    secure_user = SECURE_USER.format(
        vuln_type=task.get("vuln_type", "unknown"),
        cwe=task.get("cwe", "N/A"),
        standalone_code=standalone_code[:4000],
    )
    secure_code = call_llm(SECURE_SYSTEM, secure_user, max_tokens=4000)
    if secure_code:
        secure_code = strip_fences(secure_code)
        secure_file = task_dir / f"standalone_secure.{ext}"
        secure_file.write_text(secure_code, encoding="utf-8")
        result["secure"] = str(secure_file)
        print("OK", file=sys.stderr)
    else:
        print("FAIL", file=sys.stderr)
    time.sleep(0.5)

    # --- 4. Generate broken variant ---
    print("    broken...", end=" ", flush=True, file=sys.stderr)
    broken_user = BROKEN_USER.format(
        standalone_code=standalone_code[:4000],
    )
    broken_code = call_llm(BROKEN_SYSTEM, broken_user, max_tokens=4000)
    if broken_code:
        broken_code = strip_fences(broken_code)
        broken_file = task_dir / f"standalone_broken.{ext}"
        broken_file.write_text(broken_code, encoding="utf-8")
        result["broken"] = str(broken_file)
        print("OK", file=sys.stderr)
    else:
        print("FAIL", file=sys.stderr)
    time.sleep(0.5)

    # --- 5. Generate run.sh ---
    run_sh = generate_run_sh(task, ext)
    run_sh_file = task_dir / "run.sh"
    run_sh_file.write_text(run_sh, encoding="utf-8")
    run_sh_file.chmod(0o755)
    result["run_sh"] = str(run_sh_file)

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def regenerate_tests_only(task_dir: Path, task: Dict) -> Dict:
    """Regenerate only the test file for a task with an existing standalone file."""
    result = {"task_id": task.get("task_id", task_dir.name)}
    lang = task.get("language", "javascript")
    ext = "py" if lang == "python" else "js"

    standalone_file = task_dir / f"standalone.{ext}"
    if not standalone_file.exists():
        result["error"] = f"standalone.{ext} not found"
        return result

    standalone_code = standalone_file.read_text(encoding="utf-8")

    print("    tests...", end=" ", flush=True, file=sys.stderr)
    test_user = TEST_USER.format(
        language=lang,
        ext=ext,
        func_name=task.get("vuln_function_name", "func"),
        standalone_code=standalone_code[:3000],
    )
    test_code = call_llm(TEST_SYSTEM, test_user, max_tokens=3000)
    if test_code:
        test_code = strip_fences(test_code)
        tests_dir = task_dir / "tests"
        tests_dir.mkdir(exist_ok=True)
        test_file = tests_dir / f"test_standalone.{ext}"
        test_file.write_text(test_code, encoding="utf-8")
        result["tests"] = str(test_file)
        print("OK", file=sys.stderr)
    else:
        print("FAIL", file=sys.stderr)

    time.sleep(0.5)
    return result


def main() -> None:
    load_env()

    ap = argparse.ArgumentParser(description="Create Level-1 standalone tasks")
    ap.add_argument("--tasks-dir", type=Path,
                    default=Path(__file__).parent / "data" / "tasks")
    ap.add_argument("--tasks-jsonl", type=Path,
                    default=Path(__file__).parent / "data" / "tasks_function_level.jsonl")
    ap.add_argument("--force", action="store_true",
                    help="Overwrite existing standalone files")
    ap.add_argument("--task", type=str,
                    help="Process only this task ID (substring match)")
    ap.add_argument("--tests-only", action="store_true",
                    help="Only regenerate tests (keep existing standalone files)")
    args = ap.parse_args()

    required = ["AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        print(f"[error] Missing env vars: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    # Load tasks from JSONL
    tasks_by_id = {}
    if args.tasks_jsonl.exists():
        with open(args.tasks_jsonl, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    t = json.loads(line)
                    tasks_by_id[t["task_id"]] = t

    task_dirs = sorted(d for d in args.tasks_dir.iterdir() if d.is_dir())
    print(f"Found {len(task_dirs)} task directories.", file=sys.stderr)

    results = []
    for i, task_dir in enumerate(task_dirs, 1):
        task_id = task_dir.name

        if args.task and args.task not in task_id:
            continue

        if not args.force and (task_dir / "standalone.js").exists():
            print(f"  [{i}/{len(task_dirs)}] {task_id[:55]} SKIP", file=sys.stderr)
            continue
        if not args.force and (task_dir / "standalone.py").exists():
            print(f"  [{i}/{len(task_dirs)}] {task_id[:55]} SKIP", file=sys.stderr)
            continue

        task = tasks_by_id.get(task_id)
        if not task:
            task_json = task_dir / "task.json"
            if task_json.exists():
                task = json.loads(task_json.read_text(encoding="utf-8"))
            else:
                print(f"  [{i}/{len(task_dirs)}] SKIP (no metadata)", file=sys.stderr)
                continue

        print(f"  [{i}/{len(task_dirs)}] {task_id[:55]}", file=sys.stderr)
        if args.tests_only:
            result = regenerate_tests_only(task_dir, task)
        else:
            result = process_task(task_dir, task)
        results.append(result)

        if "error" in result:
            print(f"    ERROR: {result['error']}", file=sys.stderr)

    # Save results
    out = args.tasks_dir.parent / "level1_results.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nDone. Results: {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
