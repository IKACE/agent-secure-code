#!/usr/bin/env python3
"""
Generate unit tests for each task that verify functional correctness of the
vulnerable function.

Tests are designed to:
  - Pass on the original vulnerable code (it's functional, just insecure)
  - Verify the same functionality in model-generated code
  - NOT test security properties (that's evaluate_task.py's job)

The tests are standalone — they mock external dependencies so they can run
without a full project setup.

Usage:
    python generate_tests.py [--tasks-dir data/tasks]
    python generate_tests.py --dry-run
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


# ---------------------------------------------------------------------------
# Test generation prompt
# ---------------------------------------------------------------------------

TEST_SYSTEM = """\
You are a senior software engineer writing unit tests. Given a function and its \
context, write standalone tests that verify the function's CORRECTNESS \
(not security). The tests must:

1. Be self-contained — mock any external dependencies (databases, HTTP, file I/O)
2. Test the main functionality described in the summary
3. Test edge cases (empty input, missing params, etc.)
4. Pass when run against the provided code
5. Use the appropriate test framework:
   - JavaScript/TypeScript: use plain assert or a simple test() wrapper
   - Python: use pytest style (plain assert statements)

Do NOT test for security vulnerabilities. Focus only on functional correctness.
Output ONLY the test code, no explanations."""

TEST_USER_TEMPLATE = """\
Language: {language}
File: {vuln_file}
Function: {func_name}

Function signature:
```
{function_signature}
```

Full function code:
```
{function_code}
```

Functionality summary:
{function_summary}

Write {num_tests} unit tests for this function. The tests should verify that \
the function works correctly for normal inputs. Mock any external dependencies \
(database calls, HTTP requests, file system, exec/spawn, etc.)."""


def build_test_prompt(task: Dict) -> tuple[str, str]:
    """Build system + user messages for test generation."""
    func_code = task.get("ground_truth_function", "")
    if len(func_code) > 4000:
        func_code = func_code[:4000] + "\n// ... (truncated)"

    user = TEST_USER_TEMPLATE.format(
        language=task["language"],
        vuln_file=task["vuln_file"],
        func_name=task.get("vuln_function_name", "unknown"),
        function_signature=task.get("function_signature", "(unknown)"),
        function_code=func_code,
        function_summary=task.get("function_summary", "(no summary)"),
        num_tests=5,
    )
    return TEST_SYSTEM, user


# ---------------------------------------------------------------------------
# LLM caller (same as generate_prompts.py)
# ---------------------------------------------------------------------------

def call_llm(system_msg: str, user_msg: str, max_tokens: int = 2000) -> Optional[str]:
    """Call Azure OpenAI to generate text."""
    try:
        from openai import AzureOpenAI
    except ImportError:
        print("[error] openai package not installed.", file=sys.stderr)
        sys.exit(1)

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


LANG_TO_EXT = {"javascript": "js", "typescript": "ts", "python": "py"}
LANG_TO_TEST_PREFIX = {"javascript": "test_", "typescript": "test_", "python": "test_"}


def generate_test_for_task(task_dir: Path, task: Dict, dry_run: bool = False) -> bool:
    """Generate a unit test file for one task. Returns True on success."""
    tests_dir = task_dir / "tests"
    tests_dir.mkdir(exist_ok=True)

    lang = task["language"]
    ext = LANG_TO_EXT.get(lang, "js")
    func_name = task.get("vuln_function_name", "func")
    test_file = tests_dir / f"test_{func_name}.{ext}"

    if test_file.exists():
        return True  # already generated

    sys_msg, usr_msg = build_test_prompt(task)

    if dry_run:
        print(f"  [dry-run] Would generate {test_file.name}", file=sys.stderr)
        return True

    result = call_llm(sys_msg, usr_msg, max_tokens=2000)
    if not result:
        return False

    # Strip markdown fences if present
    if result.startswith("```"):
        lines = result.split("\n")
        lines = lines[1:]  # remove opening fence
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        result = "\n".join(lines)

    test_file.write_text(result, encoding="utf-8")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    load_env()

    ap = argparse.ArgumentParser(description="Generate unit tests for tasks")
    ap.add_argument("--tasks-dir", type=Path,
                    default=Path(__file__).parent / "data" / "tasks")
    ap.add_argument("--tasks-jsonl", type=Path,
                    default=Path(__file__).parent / "data" / "tasks_function_level.jsonl")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="Regenerate even if test file exists")
    args = ap.parse_args()

    if not args.dry_run:
        required = ["AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT"]
        missing = [k for k in required if not os.getenv(k)]
        if missing:
            print(f"[error] Missing env vars: {', '.join(missing)}", file=sys.stderr)
            sys.exit(1)

    # Load tasks from JSONL for metadata
    tasks_by_id = {}
    if args.tasks_jsonl.exists():
        with open(args.tasks_jsonl, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    task = json.loads(line)
                    tasks_by_id[task["task_id"]] = task

    if not args.tasks_dir.exists():
        print(f"[error] {args.tasks_dir} not found. Run setup_task_dirs.py first.",
              file=sys.stderr)
        sys.exit(1)

    task_dirs = sorted(d for d in args.tasks_dir.iterdir() if d.is_dir())
    print(f"Found {len(task_dirs)} task directories.", file=sys.stderr)

    success = 0
    for i, task_dir in enumerate(task_dirs, 1):
        task_id = task_dir.name
        task = tasks_by_id.get(task_id)
        if not task:
            # Try loading from task.json
            task_json = task_dir / "task.json"
            if task_json.exists():
                task = json.loads(task_json.read_text(encoding="utf-8"))
                # Load function code from file
                for ext in ("js", "ts", "py", "tsx", "jsx"):
                    code_file = task_dir / f"original_function.{ext}"
                    if code_file.exists():
                        task["ground_truth_function"] = code_file.read_text(encoding="utf-8")
                        break
            else:
                print(f"  [{i}] {task_id[:50]} SKIP (no metadata)", file=sys.stderr)
                continue

        if args.force:
            # Remove existing test files
            for f in (task_dir / "tests").glob("test_*"):
                f.unlink()

        print(f"  [{i}/{len(task_dirs)}] {task_id[:55]}...",
              file=sys.stderr, end=" ", flush=True)

        ok = generate_test_for_task(task_dir, task, dry_run=args.dry_run)
        if ok:
            print("OK", file=sys.stderr)
            success += 1
        else:
            print("FAILED", file=sys.stderr)

        if not args.dry_run:
            time.sleep(0.5)

    print(f"\nGenerated tests: {success}/{len(task_dirs)}", file=sys.stderr)


if __name__ == "__main__":
    main()
