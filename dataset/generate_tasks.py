#!/usr/bin/env python3
"""
Generate function-level security evaluation tasks from AI-assisted commits
with known true-positive vulnerabilities.

Two task tiers:
  Tier 1 (function-level): Mask only the vulnerable function body.
          The model must fill in <MASKED> — easy to evaluate with targeted SAST.
  Tier 2 (feature-level):  Natural-language prompt for the whole feature.
          More realistic but harder to evaluate.

This script produces Tier-1 tasks.  generate_prompts.py adds Tier-2 prompts.

Data source: ai_commit_vulnerability_summary.json produced by Vulnhalla
             analysis of GitHub AI-assisted commits.

Usage:
    python generate_tasks.py [--limit 10] [--severity high]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Paths (overridable via env)
# ---------------------------------------------------------------------------
DB_ROOT = Path(os.getenv(
    "DB_ROOT", "/mnt/storage/yilegu/patch_analysis/ai_commit_dbs"
))
WORKSPACE_ROOT = Path(os.getenv(
    "WORKSPACE_ROOT", "/mnt/storage/yilegu/patch_analysis/ai_commit_dbs/workspace"
))
VULN_SUMMARY = Path(os.getenv(
    "VULN_SUMMARY",
    "/home/yilegu/agent-secure-code-gen/github_study/patch_analysis/"
    "ai_commit_analysis/ai_commit_vulnerability_summary.json",
))

# High-severity vuln types (RCE, data theft, account takeover)
HIGH_SEVERITY_TYPES = {
    "DOM text reinterpreted as HTML",
    "Database query built from user-controlled sources",
    "Uncontrolled data used in path expression",
    "Network data written to file",
    "Server-side request forgery",
    "Partial server-side request forgery",
    "Indirect uncontrolled command line",
    "Uncontrolled command line",
    "Unsafe shell command constructed from library input",
    "Reflected cross-site scripting",
    "Stored cross-site scripting",
}

# CWE mapping
VULN_TYPE_TO_CWE = {
    "DOM text reinterpreted as HTML": "CWE-79",
    "Database query built from user-controlled sources": "CWE-89",
    "Uncontrolled data used in path expression": "CWE-22",
    "Network data written to file": "CWE-73",
    "Server-side request forgery": "CWE-918",
    "Partial server-side request forgery": "CWE-918",
    "Indirect uncontrolled command line": "CWE-78",
    "Uncontrolled command line": "CWE-78",
    "Unsafe shell command constructed from library input": "CWE-78",
    "Reflected cross-site scripting": "CWE-79",
    "Stored cross-site scripting": "CWE-79",
}

# Priority score for selection
PRIORITY = {
    "Uncontrolled command line": 10,
    "Indirect uncontrolled command line": 10,
    "Unsafe shell command constructed from library input": 10,
    "Database query built from user-controlled sources": 9,
    "Server-side request forgery": 8,
    "Partial server-side request forgery": 8,
    "Uncontrolled data used in path expression": 7,
    "Reflected cross-site scripting": 6,
    "Stored cross-site scripting": 6,
    "DOM text reinterpreted as HTML": 5,
    "Network data written to file": 4,
}


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def git_show_file(workspace: Path, sha: str, filepath: str) -> str:
    """Get file content at a specific commit."""
    if not workspace.exists() or not (workspace / ".git").exists():
        return ""
    try:
        r = subprocess.run(
            ["git", "show", f"{sha}:{filepath}"],
            cwd=str(workspace), capture_output=True, text=True, timeout=30,
        )
        return r.stdout if r.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def git_diff_file(workspace: Path, parent_sha: str, sha: str, filepath: str) -> str:
    """Get git diff for a single file between parent and commit."""
    if not workspace.exists() or not (workspace / ".git").exists():
        return ""
    try:
        r = subprocess.run(
            ["git", "diff", f"{parent_sha}..{sha}", "--", filepath],
            cwd=str(workspace), capture_output=True, text=True, timeout=30,
        )
        return r.stdout if r.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def git_log_message(workspace: Path, sha: str) -> str:
    """Get commit message."""
    if not workspace.exists() or not (workspace / ".git").exists():
        return ""
    try:
        r = subprocess.run(
            ["git", "log", "-1", "--format=%B", sha],
            cwd=str(workspace), capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() if r.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


# ---------------------------------------------------------------------------
# Function extraction
# ---------------------------------------------------------------------------

def find_vulnerable_function(
    sha_dir: Path, vuln_file: str, vuln_line: int, language: str,
) -> Optional[Dict[str, Any]]:
    """
    Find the function containing the vulnerable line using CodeQL FunctionTree
    data stored during Vulnhalla analysis.

    Returns dict with keys: file, function_name, start_line, end_line
    or None if not found.
    """
    # Look through vulnhalla_results to find raw findings with current_function
    vuln_results_dir = sha_dir / "vulnhalla_results"
    if not vuln_results_dir.exists():
        return None

    for issue_dir in vuln_results_dir.iterdir():
        if not issue_dir.is_dir():
            continue
        for raw_file in sorted(issue_dir.glob("*_raw.json")):
            try:
                raw = json.loads(raw_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            func = raw.get("current_function", {})
            if not func:
                continue
            func_file = func.get("file", "").strip('"')
            func_start = int(func.get("start_line", 0))
            func_end = int(func.get("end_line", 0))

            # Check if this function contains our vulnerable line
            if vuln_file in func_file and func_start <= vuln_line <= func_end:
                func_name = func.get("function_name", "").strip('"')
                return {
                    "file": func_file,
                    "function_name": func_name,
                    "start_line": func_start,
                    "end_line": func_end,
                }

    # Fallback: try to find function boundaries from the FunctionTree CSV
    ft_path = sha_dir / "db" / language / "FunctionTree.csv"
    if not ft_path.exists():
        return None

    best_match = None
    best_span = float("inf")
    try:
        with open(ft_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) < 5:
                    continue
                ft_name = parts[0].strip('"')
                ft_file = parts[1].strip('"')
                try:
                    ft_start = int(parts[2].strip('"'))
                    ft_end = int(parts[4].strip('"'))
                except ValueError:
                    continue
                if vuln_file in ft_file and ft_start <= vuln_line <= ft_end:
                    span = ft_end - ft_start
                    if span < best_span:
                        best_span = span
                        best_match = {
                            "file": ft_file,
                            "function_name": ft_name,
                            "start_line": ft_start,
                            "end_line": ft_end,
                        }
    except OSError:
        pass

    return best_match


def find_matching_vulnhalla_finding(
    sha_dir: Path, vuln_file: str, vuln_line: int, issue_type: str,
) -> Optional[Tuple[Dict[str, Any], str]]:
    """
    Find the vulnhalla raw + final finding that matches this vulnerability.

    Returns (raw_json_dict, llm_explanation_text) or None.
    """
    vuln_results_dir = sha_dir / "vulnhalla_results"
    if not vuln_results_dir.exists():
        return None

    # Normalize issue_type to directory name
    issue_type_dir = issue_type.replace(" ", "_")

    # Search in the matching issue_type directory first, then all dirs
    search_dirs = []
    candidate = vuln_results_dir / issue_type_dir
    if candidate.is_dir():
        search_dirs.append(candidate)
    for d in sorted(vuln_results_dir.iterdir()):
        if d.is_dir() and d != candidate:
            search_dirs.append(d)

    for issue_dir in search_dirs:
        for raw_file in sorted(issue_dir.glob("*_raw.json")):
            try:
                raw = json.loads(raw_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            func = raw.get("current_function", {})
            if not func:
                continue
            func_file = func.get("file", "").strip('"')
            func_start = int(func.get("start_line", 0))
            func_end = int(func.get("end_line", 0))

            if vuln_file in func_file and func_start <= vuln_line <= func_end:
                # Found the matching raw finding — now get LLM explanation
                llm_explanation = _extract_llm_explanation(raw_file)
                return raw, llm_explanation

    return None


def _extract_llm_explanation(raw_file: Path) -> str:
    """
    Extract the full LLM explanation from the corresponding _final.json.

    The _final.json files use Python repr format (not valid JSON),
    so we parse them with regex to extract assistant message content.
    """
    final_file = raw_file.with_name(
        raw_file.name.replace("_raw.json", "_final.json")
    )
    if not final_file.exists():
        return ""

    try:
        content = final_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""

    # Extract all assistant content blocks from the Python repr format.
    # Content may be delimited by single or double quotes.
    parts = []

    # Pattern 1: single-quoted content
    for m in re.finditer(
        r"'role': 'assistant', 'content': '(.*?)(?:'},|', 'tool_calls':)",
        content, re.DOTALL,
    ):
        text = m.group(1).replace("\\n", "\n").replace("\\'", "'").replace('\\"', '"').strip()
        if text:
            parts.append(text)

    # Pattern 2: double-quoted content
    for m in re.finditer(
        r"""'role': 'assistant', 'content': "(.*?)(?:"},|", 'tool_calls':)""",
        content, re.DOTALL,
    ):
        text = m.group(1).replace("\\n", "\n").replace("\\'", "'").replace('\\"', '"').strip()
        if text:
            parts.append(text)

    if not parts:
        return ""

    return "\n\n---\n\n".join(parts)


def extract_function_code(file_content: str, start_line: int, end_line: int) -> str:
    """Extract function body from file content given line range (1-indexed)."""
    lines = file_content.splitlines()
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)
    return "\n".join(lines[start_idx:end_idx])


def extract_context_window(file_content: str, start_line: int, end_line: int,
                           window: int = 50) -> Tuple[str, str]:
    """Extract prefix and suffix context around the masked region."""
    lines = file_content.splitlines()
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)

    prefix_start = max(0, start_idx - window)
    suffix_end = min(len(lines), end_idx + window)

    prefix = "\n".join(lines[prefix_start:start_idx])
    suffix = "\n".join(lines[end_idx:suffix_end])
    return prefix, suffix


# ---------------------------------------------------------------------------
# Smart masking — keep signature visible, mask vuln-relevant region
# ---------------------------------------------------------------------------

def _extract_function_signature(
    file_content: str, start_line: int, language: str,
) -> Tuple[str, int]:
    """
    Extract the function signature (declaration lines) and find where the
    body starts.

    Returns (signature_text, body_start_line) where body_start_line is
    1-indexed and points to the first line after the signature.
    """
    lines = file_content.splitlines()
    start_idx = max(0, start_line - 1)

    if language == "python":
        for i in range(start_idx, min(start_idx + 10, len(lines))):
            if lines[i].rstrip().endswith(":"):
                sig = "\n".join(lines[start_idx : i + 1])
                return sig, i + 2  # 1-indexed
        return lines[start_idx], start_line + 1
    else:
        # JS/TS/Java: signature ends at line ending with '{'
        for i in range(start_idx, min(start_idx + 15, len(lines))):
            stripped = lines[i].rstrip()
            if stripped.endswith("{"):
                sig = "\n".join(lines[start_idx : i + 1])
                return sig, i + 2
        return lines[start_idx], start_line + 1


def _parse_codeql_relevant_lines(
    codeql_issue: str, vuln_file: str, func_start: int, func_end: int,
) -> List[int]:
    """
    Extract source/sink line numbers from the CodeQL issue header
    (Message + Location fields), limited to lines within the target function.

    These are more precise than the ``### Code`` section which often dumps the
    entire function.
    """
    file_basename = vuln_file.rsplit("/", 1)[-1] if "/" in vuln_file else vuln_file
    lines: List[int] = []

    # Extract line references from Message and Location lines
    # Pattern: filename.ext:NNN  (e.g. route.ts:8, server.mjs:140)
    header = codeql_issue.split("### Code")[0] if "### Code" in codeql_issue else codeql_issue
    for m in re.finditer(r"[\w._-]+\.(?:ts|js|py|tsx|jsx|html|mjs):(\d+)", header):
        lineno = int(m.group(1))
        if func_start <= lineno <= func_end:
            lines.append(lineno)

    return sorted(set(lines))


def _compute_mask_region(
    body_start: int,
    func_end: int,
    vuln_line: int,
    codeql_lines: List[int],
    threshold: int = 50,
    padding: int = 3,
) -> Tuple[int, int]:
    """
    Determine what to mask within the function body.

    * Short bodies (≤ *threshold* lines): mask the whole body.
    * Long bodies: mask from (earliest relevant line − padding) to
      (latest relevant line + padding), clamped to the body range.
      If the resulting span covers > 80 % of the body, mask everything.

    Returns ``(mask_start, mask_end)`` as 1-indexed inclusive line numbers.
    """
    body_length = func_end - body_start + 1

    if body_length <= threshold or not codeql_lines:
        return body_start, func_end

    relevant = sorted(set(codeql_lines + [vuln_line]))
    span_start = max(body_start, min(relevant) - padding)
    span_end = min(func_end, max(relevant) + padding)

    if (span_end - span_start + 1) > body_length * 0.8:
        return body_start, func_end

    return span_start, span_end


def mask_region_in_file(
    file_content: str, mask_start: int, mask_end: int,
) -> str:
    """Replace lines *mask_start* .. *mask_end* (1-indexed, inclusive) with
    a single ``<MASKED>`` placeholder, preserving indentation."""
    lines = file_content.splitlines()
    start_idx = max(0, mask_start - 1)
    end_idx = min(len(lines), mask_end)

    if start_idx >= len(lines):
        return file_content

    indent = lines[start_idx][: len(lines[start_idx]) - len(lines[start_idx].lstrip())]
    return "\n".join(lines[:start_idx] + [indent + "<MASKED>"] + lines[end_idx:])


# ---------------------------------------------------------------------------
# Task building
# ---------------------------------------------------------------------------

def _get_vulnhalla_verdict(final_file: Path) -> str:
    """
    Extract the Vulnhalla LLM's actual security verdict from a _final.json.

    Returns one of: 'confirmed', 'probably_not', 'needs_code', 'secure', 'unknown'.
    The summary JSON's status='true' is unreliable — it doesn't reflect the
    LLM's final assessment.  We parse the actual assistant messages instead.
    """
    try:
        content = final_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return "unknown"

    # Skip system prompt (which merely defines the status codes)
    user_start = content.find("'role': 'user'")
    if user_start < 0:
        user_start = 0
    after_system = content[user_start:]

    has_1337 = bool(re.search(r"\*\*1337\*\*", after_system))
    has_7331 = bool(re.search(r"\*\*7331\*\*", after_system))
    has_3713 = bool(re.search(r"\*\*3713\*\*", after_system))
    has_1007 = bool(re.search(r"\*\*1007\*\*", after_system))

    if has_1337 and not has_7331 and not has_1007:
        return "confirmed"
    if has_7331 and has_3713:
        return "probably_not"
    if has_7331:
        return "needs_code"
    if has_1007:
        return "secure"
    if has_1337:
        return "confirmed"
    return "unknown"


def _is_sink_in_function(raw: Dict, func_start: int, func_end: int) -> bool:
    """
    Check whether the CodeQL sink (the dangerous operation) is inside the
    function we would mask.  If the sink is in a *different* function, masking
    this function alone won't produce a meaningful security task.
    """
    prompt = raw.get("prompt", "")
    loc = re.search(r"Location: look at \S+?:(\d+)", prompt)
    if not loc:
        return True  # can't tell — assume yes
    sink_line = int(loc.group(1))
    return func_start <= sink_line <= func_end


def collect_high_severity_findings(
    vuln_summary_path: Path, db_root: Path,
) -> List[Dict[str, Any]]:
    """
    Load vulnerability summary and collect high-severity findings that are
    **confirmed vulnerable** by the Vulnhalla LLM (status code 1337) and
    whose sink is inside the vulnerable function (so masking it creates a
    meaningful task).
    """
    data = json.loads(vuln_summary_path.read_text(encoding="utf-8"))
    findings = data.get("findings", [])

    candidates = [
        f for f in findings
        if f.get("status") == "true" and f.get("issue_type") in HIGH_SEVERITY_TYPES
    ]
    print(f"  Candidates from summary (status=true, high-sev): {len(candidates)}",
          file=sys.stderr)

    verified = []
    skipped_verdict = 0
    skipped_sink = 0
    for f in candidates:
        repo_slug = f["repo"].replace("/", "__")
        sha = f["sha"]
        line = f["line"]
        issue_dir = f["issue_type"].replace(" ", "_")

        # Locate SHA directory
        sha_dir = _find_sha_dir(db_root, repo_slug, sha)
        if sha_dir is None:
            continue

        results_dir = sha_dir / "vulnhalla_results" / issue_dir
        if not results_dir.is_dir():
            continue

        # Find the matching raw finding
        for raw_file in sorted(results_dir.glob("*_raw.json")):
            try:
                raw = json.loads(raw_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            cf = raw.get("current_function", {})
            func_start = int(cf.get("start_line", 0))
            func_end = int(cf.get("end_line", 0))
            if not (func_start <= line <= func_end):
                continue

            # Check 1: LLM actually confirmed vulnerability
            final_file = raw_file.with_name(
                raw_file.name.replace("_raw.json", "_final.json")
            )
            if final_file.exists():
                verdict = _get_vulnhalla_verdict(final_file)
                if verdict != "confirmed":
                    skipped_verdict += 1
                    break

            # Check 2: sink is inside the function we'd mask
            if not _is_sink_in_function(raw, func_start, func_end):
                skipped_sink += 1
                break

            verified.append(f)
            break

    print(f"  Skipped (LLM verdict not confirmed): {skipped_verdict}",
          file=sys.stderr)
    print(f"  Skipped (sink outside masked function): {skipped_sink}",
          file=sys.stderr)
    return verified


def _find_sha_dir(db_root: Path, repo_slug: str, sha: str) -> Optional[Path]:
    """Locate the SHA directory under db_root/repo_slug/."""
    repo_db = db_root / repo_slug
    if not repo_db.exists():
        return None
    prefix = sha[:8]
    for d in repo_db.iterdir():
        if d.is_dir() and d.name.startswith(prefix):
            return d
    return None


def group_by_commit(findings: List[Dict]) -> Dict[Tuple[str, str], List[Dict]]:
    """Group findings by (repo, sha)."""
    groups = defaultdict(list)
    for f in findings:
        groups[(f["repo"], f["sha"])].append(f)
    return dict(groups)


def resolve_relative_path(abs_path: str, repo_slug: str) -> str:
    """Convert absolute workspace path to repo-relative path."""
    marker = repo_slug + "/"
    idx = abs_path.find(marker)
    if idx >= 0:
        return abs_path[idx + len(marker):]
    return abs_path.lstrip("/")


def _build_vuln_detail(
    sha_dir: Path,
    rel_vuln_file: str,
    vuln_line: int,
    issue_type: str,
    finding: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build the vuln_detail sub-dict containing:
      - codeql_issue: the CodeQL issue description, message, location, hints, and
        code snippet (from the vulnhalla *_raw.json prompt field)
      - llm_explanation: the full Vulnhalla LLM verification explanation
        (from the *_final.json assistant messages)
      - original_finding: the entry from ai_commit_vulnerability_summary.json
    """
    detail: Dict[str, Any] = {
        "codeql_issue": None,
        "llm_explanation": None,
        "original_finding": {
            "repo": finding.get("repo"),
            "sha": finding.get("sha"),
            "agents": finding.get("agents"),
            "language": finding.get("language"),
            "issue_type": finding.get("issue_type"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "status": finding.get("status"),
            "llm_explanation": finding.get("llm_explanation"),
        },
    }

    result = find_matching_vulnhalla_finding(
        sha_dir, rel_vuln_file, vuln_line, issue_type,
    )
    if result is not None:
        raw_json, llm_explanation = result
        detail["codeql_issue"] = raw_json.get("prompt")
        detail["llm_explanation"] = llm_explanation

    return detail


def build_function_level_task(
    repo: str,
    sha: str,
    finding: Dict[str, Any],
    workspace_root: Path,
    db_root: Path,
) -> Optional[Dict[str, Any]]:
    """
    Build a single function-level task from a true-positive finding.

    Returns a task dict or None if we can't extract the needed data.
    """
    repo_slug = repo.replace("/", "__")
    workspace = workspace_root / repo_slug
    if not workspace.exists():
        return None

    # Locate SHA directory in DB_ROOT
    sha_dir = _find_sha_dir(db_root, repo_slug, sha)
    if sha_dir is None:
        return None

    language = finding.get("language", "javascript")
    vuln_line = finding.get("line", 0)
    issue_type = finding.get("issue_type", "")
    abs_vuln_file = finding.get("file", "")
    rel_vuln_file = resolve_relative_path(abs_vuln_file, repo_slug)

    # Get commit info
    commit_info_path = sha_dir / "commit_info.json"
    commit_info = {}
    if commit_info_path.exists():
        try:
            commit_info = json.loads(commit_info_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    parent_sha = commit_info.get("parent_sha")

    # Find the vulnerable function
    func_info = find_vulnerable_function(sha_dir, rel_vuln_file, vuln_line, language)
    if func_info is None:
        # Fallback: use a window around the vulnerable line
        func_info = {
            "file": abs_vuln_file,
            "function_name": "(unknown)",
            "start_line": max(1, vuln_line - 15),
            "end_line": vuln_line + 15,
        }

    # Read the file content at the vulnerable commit
    file_content = git_show_file(workspace, sha, rel_vuln_file)
    if not file_content:
        # Try reading from disk (workspace may be checked out at this sha)
        file_path = workspace / rel_vuln_file
        if file_path.exists():
            try:
                file_content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return None
        else:
            return None

    start_line = func_info["start_line"]
    end_line = func_info["end_line"]

    # Validate line range
    total_lines = len(file_content.splitlines())
    if start_line < 1 or start_line > total_lines:
        return None
    end_line = min(end_line, total_lines)
    if end_line - start_line < 2:
        return None
    # Skip tiny functions (<10 lines) — too little context for a security task
    if end_line - start_line < 10:
        return None
    # Cap very large functions at 300 lines (we can now mask a subset)
    if end_line - start_line > 300:
        end_line = start_line + 300

    # --- Vulnerability detail from Vulnhalla ---
    vuln_detail = _build_vuln_detail(
        sha_dir, rel_vuln_file, vuln_line, issue_type, finding,
    )

    # --- Smart masking ---
    # 1) Extract function signature (always visible to the model)
    func_signature, body_start = _extract_function_signature(
        file_content, start_line, language,
    )

    # 2) Parse CodeQL source/sink lines to find vuln-relevant span
    codeql_issue = (vuln_detail.get("codeql_issue") or "")
    codeql_lines = _parse_codeql_relevant_lines(
        codeql_issue, rel_vuln_file, start_line, end_line,
    )

    # 3) Compute mask region (may be a subset of the function body)
    mask_start, mask_end = _compute_mask_region(
        body_start, end_line, vuln_line, codeql_lines,
    )

    # Extract the full vulnerable function code
    vuln_function_code = extract_function_code(file_content, start_line, end_line)

    # Extract only the masked region (= what the model must generate)
    ground_truth_masked = extract_function_code(file_content, mask_start, mask_end)

    # Create masked file
    masked_file_content = mask_region_in_file(file_content, mask_start, mask_end)

    # Extract context window
    prefix, suffix = extract_context_window(file_content, start_line, end_line)

    # Get diff for this file if parent exists
    diff = ""
    if parent_sha and parent_sha != "NONE":
        diff = git_diff_file(workspace, parent_sha, sha, rel_vuln_file)

    # Get commit message
    commit_message = commit_info.get("commit_message", "")
    if not commit_message:
        commit_message = git_log_message(workspace, sha)

    short_sha = sha[:8]
    task_id = (
        f"{repo_slug}__{short_sha}__{issue_type.replace(' ', '_')}"
        f"__{rel_vuln_file.replace('/', '_')}_L{vuln_line}"
    )

    cwe = VULN_TYPE_TO_CWE.get(issue_type, "")

    return {
        # -- identification --
        "task_id": task_id,
        "repo": repo,
        "repo_slug": repo_slug,
        "sha": sha,
        "parent_sha": parent_sha,
        "language": language,
        "agents": finding.get("agents", []),

        # -- vulnerability metadata --
        "vuln_type": issue_type,
        "cwe": cwe,
        "severity": "high",
        "vuln_file": rel_vuln_file,
        "vuln_line": vuln_line,
        "vuln_function_name": func_info["function_name"],
        "vuln_lines": [start_line, end_line],

        # -- original vulnerability detail (from Vulnhalla / CodeQL) --
        "vuln_detail": vuln_detail,

        # -- smart masking --
        "function_signature": func_signature,
        "mask_region": [mask_start, mask_end],
        "masked_file_content": masked_file_content,
        "ground_truth_function": vuln_function_code,
        "ground_truth_masked": ground_truth_masked,
        "context_prefix": prefix,
        "context_suffix": suffix,

        # -- full file for reference --
        "full_file_content": file_content,
        "file_diff": diff,
        "commit_message": commit_message,

        # -- prompt placeholder (filled by generate_prompts.py) --
        "function_summary": None,
        "tier1_prompt": None,
        "tier2_prompt": None,
    }


def _func_key(task: Dict[str, Any]) -> str:
    """Unique key for a (file, function-range) to deduplicate overlapping findings."""
    return f"{task['vuln_file']}:{task['vuln_lines'][0]}-{task['vuln_lines'][1]}"


def select_diverse_tasks(
    tasks: List[Dict[str, Any]], limit: int
) -> List[Dict[str, Any]]:
    """Select a diverse set of tasks prioritizing severity and type coverage.

    Deduplicates tasks that point to the same function (different vuln types
    in the same code range).  When two findings share a function, keep the
    higher-priority one.
    """
    # --- Deduplicate on (file, line-range) keeping highest priority ---
    best_by_func: Dict[str, Dict[str, Any]] = {}
    for task in tasks:
        key = _func_key(task)
        prev = best_by_func.get(key)
        if prev is None or PRIORITY.get(task["vuln_type"], 0) > PRIORITY.get(prev["vuln_type"], 0):
            best_by_func[key] = task
    deduped = list(best_by_func.values())

    if len(deduped) <= limit:
        return deduped

    # Sort by priority (highest first)
    tasks_sorted = sorted(
        deduped,
        key=lambda t: PRIORITY.get(t["vuln_type"], 0),
        reverse=True,
    )

    selected = []
    selected_ids = set()
    type_covered = set()

    # Phase 1: one of each vuln type, highest priority first
    for task in tasks_sorted:
        if task["vuln_type"] not in type_covered:
            selected.append(task)
            selected_ids.add(task["task_id"])
            type_covered.add(task["vuln_type"])
        if len(selected) >= limit:
            return selected[:limit]

    # Phase 2: different repos
    repo_covered = {t["repo"] for t in selected}
    for task in tasks_sorted:
        if task["task_id"] not in selected_ids and task["repo"] not in repo_covered:
            selected.append(task)
            selected_ids.add(task["task_id"])
            repo_covered.add(task["repo"])
        if len(selected) >= limit:
            return selected[:limit]

    # Phase 3: fill remaining
    for task in tasks_sorted:
        if task["task_id"] not in selected_ids:
            selected.append(task)
            selected_ids.add(task["task_id"])
        if len(selected) >= limit:
            break

    return selected[:limit]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate function-level security evaluation tasks"
    )
    ap.add_argument("--vuln-summary", type=Path, default=VULN_SUMMARY,
                    help="Path to ai_commit_vulnerability_summary.json")
    ap.add_argument("--db-root", type=Path, default=DB_ROOT)
    ap.add_argument("--workspace-root", type=Path, default=WORKSPACE_ROOT)
    ap.add_argument("--output", type=Path,
                    default=Path(__file__).parent / "data" / "tasks_function_level.jsonl")
    ap.add_argument("--limit", type=int, default=10,
                    help="Number of tasks to generate")
    ap.add_argument("--severity", choices=["high", "all"], default="high")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    print(f"Loading vulnerability summary from {args.vuln_summary}...", file=sys.stderr)
    findings = collect_high_severity_findings(args.vuln_summary, args.db_root)
    print(f"Verified {len(findings)} high-severity true positives.", file=sys.stderr)

    by_commit = group_by_commit(findings)
    print(f"Across {len(by_commit)} unique commits.", file=sys.stderr)

    # Build tasks — one per finding (one vulnerable function = one task)
    all_tasks = []
    errors = Counter()
    for (repo, sha), commit_findings in sorted(by_commit.items()):
        for finding in commit_findings:
            task = build_function_level_task(
                repo, sha, finding, args.workspace_root, args.db_root,
            )
            if task is None:
                errors["build_failed"] += 1
                continue
            if not task["ground_truth_function"].strip():
                errors["empty_function"] += 1
                continue
            all_tasks.append(task)

    print(f"Built {len(all_tasks)} tasks. Errors: {dict(errors)}", file=sys.stderr)

    # Select diverse subset
    selected = select_diverse_tasks(all_tasks, args.limit)
    print(f"Selected {len(selected)} tasks (limit={args.limit}).", file=sys.stderr)

    # Print stats
    type_counts = Counter(t["vuln_type"] for t in selected)
    lang_counts = Counter(t["language"] for t in selected)
    agent_counts = Counter(a for t in selected for a in t["agents"])

    print(f"\n--- Task Statistics ---", file=sys.stderr)
    print(f"Total: {len(selected)}", file=sys.stderr)
    print(f"\nVuln types:", file=sys.stderr)
    for vt, cnt in type_counts.most_common():
        print(f"  {vt}: {cnt}", file=sys.stderr)
    print(f"\nLanguages:", file=sys.stderr)
    for lang, cnt in lang_counts.most_common():
        print(f"  {lang}: {cnt}", file=sys.stderr)
    print(f"\nAgents:", file=sys.stderr)
    for agent, cnt in agent_counts.most_common():
        print(f"  {agent}: {cnt}", file=sys.stderr)

    # Show task summaries
    print(f"\n--- Selected Tasks ---", file=sys.stderr)
    for i, t in enumerate(selected, 1):
        func_lines = t["vuln_lines"][1] - t["vuln_lines"][0]
        print(f"  {i}. {t['repo']} ({t['sha'][:8]})", file=sys.stderr)
        print(f"     Type: {t['vuln_type']} ({t['cwe']})", file=sys.stderr)
        print(f"     File: {t['vuln_file']}:{t['vuln_line']}", file=sys.stderr)
        print(f"     Function: {t['vuln_function_name']} "
              f"(lines {t['vuln_lines'][0]}-{t['vuln_lines'][1]}, "
              f"{func_lines} lines)", file=sys.stderr)
        print(file=sys.stderr)

    if args.dry_run:
        print("[dry-run] Not writing output.", file=sys.stderr)
        return

    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for task in selected:
            f.write(json.dumps(task, ensure_ascii=False) + "\n")
    print(f"Wrote {len(selected)} tasks to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
