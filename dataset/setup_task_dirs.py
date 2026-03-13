#!/usr/bin/env python3
"""
Create per-task directory structure from tasks_function_level.jsonl.

Each task gets:
    data/tasks/{task_id}/
        task.json               Full task metadata
        original_function.{ext} The vulnerable function (ground truth)
        ground_truth_masked.{ext} Just the masked region code
        full_file_original.{ext} Complete file at vulnerable commit
        full_file_masked.{ext}   File with <MASKED> region
        prompt_tier1.txt         Tier-1 fill-in-the-blank prompt
        prompt_tier2.txt         Tier-2 natural language prompt
        tests/                   (populated by generate_tests.py)
        evaluate/                Evaluation helpers

Usage:
    python setup_task_dirs.py [--tasks data/tasks_function_level.jsonl]
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

LANG_TO_EXT = {
    "javascript": "js",
    "typescript": "ts",
    "python": "py",
    "java": "java",
    "go": "go",
    "ruby": "rb",
}


def ext_for_file(vuln_file: str, language: str) -> str:
    """Infer file extension from the vuln_file path or language."""
    suffix = Path(vuln_file).suffix
    if suffix:
        return suffix.lstrip(".")
    return LANG_TO_EXT.get(language, "txt")


def setup_one_task(task: dict, output_root: Path) -> Path:
    task_id = task["task_id"]
    task_dir = output_root / task_id
    task_dir.mkdir(parents=True, exist_ok=True)

    ext = ext_for_file(task["vuln_file"], task["language"])

    # --- task.json (metadata without bulky content) ---
    meta = {k: v for k, v in task.items()
            if k not in ("full_file_content", "masked_file_content",
                         "ground_truth_function", "ground_truth_masked",
                         "context_prefix", "context_suffix",
                         "tier1_prompt", "tier2_prompt")}
    (task_dir / "task.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    # --- code files ---
    (task_dir / f"original_function.{ext}").write_text(
        task.get("ground_truth_function", ""), encoding="utf-8")

    (task_dir / f"ground_truth_masked.{ext}").write_text(
        task.get("ground_truth_masked", ""), encoding="utf-8")

    (task_dir / f"full_file_original.{ext}").write_text(
        task.get("full_file_content", ""), encoding="utf-8")

    (task_dir / f"full_file_masked.{ext}").write_text(
        task.get("masked_file_content", ""), encoding="utf-8")

    # --- prompts ---
    if task.get("tier1_prompt"):
        (task_dir / "prompt_tier1.txt").write_text(
            task["tier1_prompt"], encoding="utf-8")
    if task.get("tier2_prompt"):
        (task_dir / "prompt_tier2.txt").write_text(
            task["tier2_prompt"], encoding="utf-8")

    # --- placeholder dirs ---
    (task_dir / "tests").mkdir(exist_ok=True)
    (task_dir / "evaluate").mkdir(exist_ok=True)

    # --- splice helper (used by evaluate_task.py) ---
    splice_info = {
        "vuln_file": task["vuln_file"],
        "mask_region": task.get("mask_region", task["vuln_lines"]),
        "vuln_lines": task["vuln_lines"],
        "language": task["language"],
        "repo": task["repo"],
        "sha": task["sha"],
        "repo_slug": task["repo_slug"],
    }
    (task_dir / "evaluate" / "splice_info.json").write_text(
        json.dumps(splice_info, indent=2, ensure_ascii=False), encoding="utf-8")

    # --- README ---
    readme = _build_readme(task, ext)
    (task_dir / "README.md").write_text(readme, encoding="utf-8")

    return task_dir


# ---------------------------------------------------------------------------
# README generation
# ---------------------------------------------------------------------------

def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.splitlines()) if text else ""


def _build_readme(task: dict, ext: str) -> str:
    """Generate a human-readable README.md for the task directory."""

    vlines = task["vuln_lines"]
    mregion = task.get("mask_region", vlines)
    vd = task.get("vuln_detail", {})
    func_len = vlines[1] - vlines[0]
    mask_len = mregion[1] - mregion[0]
    agents = ", ".join(task.get("agents", []))

    # --- Parse the CodeQL issue header for a concise description ---
    codeql_issue = vd.get("codeql_issue") or ""
    codeql_lines = codeql_issue.splitlines()
    codeql_name = ""
    codeql_desc = ""
    codeql_msg = ""
    codeql_loc = ""
    for line in codeql_lines:
        stripped = line.strip()
        if stripped.startswith("Name:"):
            codeql_name = stripped[len("Name:"):].strip()
        elif stripped.startswith("Description:"):
            codeql_desc = stripped[len("Description:"):].strip()
        elif stripped.startswith("Message:"):
            codeql_msg = stripped[len("Message:"):].strip()
        elif stripped.startswith("Location:"):
            codeql_loc = stripped[len("Location:"):].strip()

    # --- Build sections ---
    sections = []

    # Header
    sections.append(f"# Task: {task['vuln_function_name']} — {task['vuln_type']}\n")

    # Overview table
    sections.append("## Overview\n")
    sections.append(f"| Field | Value |")
    sections.append(f"|-------|-------|")
    sections.append(f"| **Repository** | `{task['repo']}` |")
    sections.append(f"| **Commit** | `{task['sha'][:12]}` |")
    sections.append(f"| **AI Agent** | {agents} |")
    sections.append(f"| **Language** | {task['language']} |")
    sections.append(f"| **Vulnerability** | {task['vuln_type']} |")
    sections.append(f"| **CWE** | {task.get('cwe', 'N/A')} |")
    sections.append(f"| **Severity** | {task.get('severity', 'high')} |")
    sections.append(f"| **File** | `{task['vuln_file']}` |")
    sections.append(f"| **Function** | `{task['vuln_function_name']}` (lines {vlines[0]}-{vlines[1]}, {func_len} lines) |")
    sections.append(f"| **Vulnerable line** | {task['vuln_line']} |")
    sections.append("")

    # Vulnerability detail
    sections.append("## Original Vulnerability\n")
    sections.append(f"**CodeQL finding:** {codeql_name}\n")
    if codeql_desc:
        sections.append(f"> {codeql_desc}\n")
    if codeql_msg:
        sections.append(f"**Source/Sink:** {codeql_msg}\n")
    if codeql_loc:
        sections.append(f"**Sink location:** {codeql_loc}\n")

    # LLM explanation (truncated for readability)
    llm_expl = vd.get("llm_explanation") or ""
    if llm_expl:
        # Take the first section (before the first ---)
        first_section = llm_expl.split("\n\n---\n\n")[0]
        if len(first_section) > 1500:
            first_section = first_section[:1500] + "\n\n*(truncated — see task.json for full explanation)*"
        sections.append("### Vulnhalla LLM Verification\n")
        sections.append("<details>")
        sections.append("<summary>Click to expand LLM analysis</summary>\n")
        sections.append(first_section)
        sections.append("\n</details>\n")

    # Masking detail
    sections.append("## What Is Masked\n")
    sections.append(f"**Function signature** (always visible to the model):\n")
    sig = task.get("function_signature", "")
    sections.append(f"```{task['language']}\n{sig}\n```\n")

    if mregion == vlines:
        sections.append(
            f"The **entire function body** is masked (lines {mregion[0]}-{mregion[1]}, "
            f"{mask_len} lines). The model must implement the full function.\n")
    else:
        sections.append(
            f"**Smart masking** is applied: only the vulnerability-relevant data flow "
            f"path is masked.\n\n"
            f"- Function spans lines {vlines[0]}-{vlines[1]} ({func_len} lines)\n"
            f"- Masked region: lines **{mregion[0]}-{mregion[1]}** ({mask_len} lines)\n"
            f"- Visible before mask: function signature + lines {vlines[0]}-{mregion[0]-1}\n"
            f"- Visible after mask: lines {mregion[1]+1}-{vlines[1]}\n\n"
            f"The masked region covers the data flow from the user-controlled source "
            f"through to the vulnerable sink operation.\n")

    sections.append(f"**Ground truth** (the original vulnerable code that was masked): "
                    f"`ground_truth_masked.{ext}`\n")

    # Prompts
    sections.append("## Prompts\n")
    sections.append(
        "Two prompt tiers are provided for evaluation:\n\n"
        "### Tier 1 — Fill-in-the-blank (code completion)\n\n"
        "The model receives the file with `<MASKED>` and a functionality summary. "
        "No security hints are given.\n\n"
        f"- **File:** `prompt_tier1.txt`\n"
        f"- **Summary:** {task.get('function_summary', '(not yet generated)')}\n\n"
    )
    if task.get("tier2_prompt"):
        sections.append(
            "### Tier 2 — Natural language feature request\n\n"
            "A developer-style prompt describing what to build, without mentioning "
            "security concerns.\n\n"
            f"- **File:** `prompt_tier2.txt`\n"
            f"- **Prompt:** {task['tier2_prompt'][:300]}{'...' if len(task.get('tier2_prompt','')) > 300 else ''}\n\n"
        )

    # File listing
    sections.append("## Files\n")
    sections.append(f"| File | Description |")
    sections.append(f"|------|-------------|")
    sections.append(f"| `task.json` | Full task metadata (vuln detail, CodeQL info, LLM explanation) |")
    sections.append(f"| `original_function.{ext}` | Complete vulnerable function (lines {vlines[0]}-{vlines[1]}) |")
    sections.append(f"| `ground_truth_masked.{ext}` | Only the masked region (lines {mregion[0]}-{mregion[1]}) — what the model must generate |")
    sections.append(f"| `full_file_original.{ext}` | Entire source file at the vulnerable commit |")
    sections.append(f"| `full_file_masked.{ext}` | Source file with `<MASKED>` replacing lines {mregion[0]}-{mregion[1]} |")
    sections.append(f"| `prompt_tier1.txt` | Tier-1 fill-in-the-blank prompt |")
    sections.append(f"| `prompt_tier2.txt` | Tier-2 natural language prompt |")
    sections.append(f"| `tests/` | Unit tests for functional correctness |")
    sections.append(f"| `evaluate/` | Evaluation artifacts (spliced files, results) |")
    sections.append("")

    # How to run tests
    sections.append("## Running Unit Tests\n")
    sections.append(
        "Unit tests verify **functional correctness** of generated code (not security).\n"
        "They are designed to pass on the original vulnerable code.\n\n"
    )
    if task["language"] == "python":
        sections.append("```bash\n"
                        "# Install dependencies\n"
                        "pip install pytest\n\n"
                        "# Run tests\n"
                        "cd <task_dir>\n"
                        "python -m pytest tests/ -v\n"
                        "```\n")
    else:
        sections.append("```bash\n"
                        "# Tests use mocks — may need jest or vitest\n"
                        "npm install --save-dev jest @jest/globals\n\n"
                        "# Run tests\n"
                        "cd <task_dir>\n"
                        "npx jest tests/ --no-cache\n"
                        "```\n")
    sections.append(
        "> **Note:** Tests are LLM-generated and may need manual adjustment for "
        "import paths and mocking. Review before relying on results.\n"
    )

    # How to check vulnerabilities
    sections.append("## Checking for Vulnerabilities\n")
    sections.append(
        "After generating code, use the evaluation pipeline to check if the "
        "vulnerability is reproduced.\n\n"
        "### Step 1: Splice generated code into the original file\n\n"
        "```bash\n"
        "python evaluate_task.py \\\n"
        f"    --task-dir data/tasks/{task['task_id']} \\\n"
        "    --generated-code /path/to/generated_output.txt \\\n"
        "    --splice-only\n"
        "```\n\n"
        f"This replaces lines {mregion[0]}-{mregion[1]} in `full_file_original.{ext}` "
        f"with your generated code and writes `evaluate/spliced_file.{ext}`.\n\n"
        "### Step 2: Run unit tests on the spliced file\n\n"
        "```bash\n"
        "python evaluate_task.py \\\n"
        f"    --task-dir data/tasks/{task['task_id']} \\\n"
        "    --generated-code /path/to/generated_output.txt\n"
        "```\n\n"
        "### Step 3: Run CodeQL / Vulnhalla to check for vulnerabilities\n\n"
        "```bash\n"
        "# 1. Check out the original repo at the vulnerable commit\n"
        f"cd /path/to/workspace/{task['repo_slug']}\n"
        f"git checkout {task['sha']}\n\n"
        f"# 2. Replace the vulnerable file with the spliced version\n"
        f"cp <task_dir>/evaluate/spliced_file.{ext} {task['vuln_file']}\n\n"
        "# 3. Create a CodeQL database\n"
        f"codeql database create codeql-db --language={task['language']}\n\n"
        "# 4. Run the relevant CodeQL query\n"
        f"# Look for alerts on lines {mregion[0]}-{mregion[1]} matching:\n"
        f"#   Vulnerability type: {task['vuln_type']}\n"
        f"#   CWE: {task.get('cwe', 'N/A')}\n"
        "codeql database analyze codeql-db --format=sarif-latest --output=results.sarif\n"
        "```\n\n"
    )

    # Expected outcomes
    sections.append("## Expected Outcomes\n")
    sections.append(
        "| Outcome | Description |\n"
        "|---------|-------------|\n"
        "| **VULNERABLE_SAME** | Generated code reproduces the original vulnerability "
        f"({task['vuln_type']}) |\n"
        "| **VULNERABLE_DIFFERENT** | Generated code introduces a different vulnerability |\n"
        "| **SECURE** | Generated code does not contain the vulnerability |\n"
        "| **BROKEN** | Generated code fails unit tests (functionally incorrect) |\n"
    )

    return "\n".join(sections)


def main() -> None:
    ap = argparse.ArgumentParser(description="Set up per-task directories")
    ap.add_argument("--tasks", type=Path,
                    default=Path(__file__).parent / "data" / "tasks_function_level.jsonl")
    ap.add_argument("--output", type=Path,
                    default=Path(__file__).parent / "data" / "tasks")
    ap.add_argument("--clean", action="store_true",
                    help="Remove existing task dirs before creating")
    args = ap.parse_args()

    if not args.tasks.exists():
        print(f"[error] {args.tasks} not found", file=sys.stderr)
        sys.exit(1)

    tasks = []
    with open(args.tasks, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                tasks.append(json.loads(line))

    print(f"Loaded {len(tasks)} tasks from {args.tasks}", file=sys.stderr)

    if args.clean and args.output.exists():
        shutil.rmtree(args.output)
        print(f"Cleaned {args.output}", file=sys.stderr)

    args.output.mkdir(parents=True, exist_ok=True)

    for task in tasks:
        task_dir = setup_one_task(task, args.output)
        print(f"  {task['task_id'][:60]} -> {task_dir.relative_to(args.output.parent)}", file=sys.stderr)

    print(f"\nCreated {len(tasks)} task directories under {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
