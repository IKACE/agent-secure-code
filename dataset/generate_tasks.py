#!/usr/bin/env python3
"""
Step 1: Build tasks.jsonl from Vulnhalla true-positive results.

Scans all vulnhalla_summary.json files under DB_ROOT, collects commits with
confirmed true-positive vulnerabilities, extracts metadata + git diffs,
and writes one JSONL record per commit.

Usage:
    python generate_tasks.py [--limit 50] [--min-tp 1] [--language javascript,python]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Defaults (overridable via .env) ──────────────────────────────────────────

DB_ROOT = Path(os.getenv(
    "DB_ROOT", "/mnt/storage/yilegu/patch_analysis/ai_commit_dbs"
))
WORKSPACE_ROOT = Path(os.getenv(
    "WORKSPACE_ROOT", "/mnt/storage/yilegu/patch_analysis/ai_commit_dbs/workspace"
))


def load_env() -> None:
    """Load .env file if present (simple key=value, no shell expansion)."""
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


def find_tp_commits(db_root: Path, min_tp: int = 1) -> List[Dict[str, Any]]:
    """Walk all vulnhalla_summary.json files and collect those with true_positives >= min_tp."""
    results = []
    for repo_dir in sorted(db_root.iterdir()):
        if not repo_dir.is_dir() or repo_dir.name in ("workspace", "errors.jsonl"):
            continue
        for sha_dir in sorted(repo_dir.iterdir()):
            if not sha_dir.is_dir():
                continue
            summary_path = sha_dir / "vulnhalla_summary.json"
            commit_info_path = sha_dir / "commit_info.json"
            if not summary_path.exists() or not commit_info_path.exists():
                continue
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                if summary.get("true_positives", 0) < min_tp:
                    continue
                commit_info = json.loads(commit_info_path.read_text(encoding="utf-8"))
                results.append({
                    "repo_slug": repo_dir.name,
                    "sha_dir": sha_dir,
                    "summary": summary,
                    "commit_info": commit_info,
                })
            except (json.JSONDecodeError, OSError) as e:
                print(f"  [warn] Error reading {sha_dir}: {e}", file=sys.stderr)
    return results


def extract_vuln_files(
    summary: Dict[str, Any], workspace_root: Path, repo_slug: str
) -> List[str]:
    """Extract vulnerable file paths (relative to repo root) from vulnhalla findings."""
    vuln_files = set()
    workspace_prefix = str(workspace_root / repo_slug) + "/"

    for itype, idata in summary.get("issue_types", {}).items():
        for finding in idata.get("findings", []):
            if finding.get("status") != "true":
                continue
            fpath = finding.get("file", "")
            if not fpath:
                continue
            # Convert absolute path to repo-relative
            if fpath.startswith(workspace_prefix):
                fpath = fpath[len(workspace_prefix):]
            elif fpath.startswith("/"):
                # Try to strip any workspace-like prefix
                parts = fpath.split(repo_slug + "/", 1)
                if len(parts) == 2:
                    fpath = parts[1]
                else:
                    fpath = fpath.lstrip("/")
            vuln_files.add(fpath)
    return sorted(vuln_files)


def extract_vuln_types(summary: Dict[str, Any]) -> List[str]:
    """Extract vulnerability types that have true positives."""
    types = []
    for itype, idata in summary.get("issue_types", {}).items():
        if isinstance(idata, dict) and idata.get("true", 0) > 0:
            types.append(itype)
    return sorted(types)


def git_diff(workspace: Path, parent_sha: str, sha: str, files: List[str]) -> str:
    """Get git diff between parent and commit for specified files."""
    if not workspace.exists() or not (workspace / ".git").exists():
        return ""
    cmd = ["git", "diff", f"{parent_sha}..{sha}", "--"] + files
    try:
        r = subprocess.run(
            cmd, cwd=str(workspace), capture_output=True, text=True, timeout=30
        )
        return r.stdout if r.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


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


def build_task_record(entry: Dict[str, Any], workspace_root: Path) -> Optional[Dict[str, Any]]:
    """Build a single task record from a TP commit entry."""
    commit_info = entry["commit_info"]
    summary = entry["summary"]
    repo_slug = entry["repo_slug"]
    sha = commit_info.get("sha", "")
    parent_sha = commit_info.get("parent_sha", "")

    # Skip commits without a parent (can't generate meaningful diff)
    if not parent_sha or parent_sha == "NONE":
        return None

    workspace = workspace_root / repo_slug
    if not workspace.exists():
        return None

    # Extract vuln files and types
    vuln_files = extract_vuln_files(summary, workspace_root, repo_slug)
    vuln_types = extract_vuln_types(summary)

    if not vuln_files:
        return None

    # Determine language
    detected_langs = commit_info.get("detected_languages", [])
    language = detected_langs[0] if detected_langs else "unknown"

    # Get diff for vulnerable files
    diff = git_diff(workspace, parent_sha, sha, vuln_files)

    # Get file contents at commit
    file_contents = {}
    for vf in vuln_files:
        content = git_show_file(workspace, sha, vf)
        if content:
            file_contents[vf] = content

    # Short SHA for task_id
    short_sha = sha[:8] if sha else "unknown"
    task_id = f"{repo_slug}__{short_sha}"

    return {
        "task_id": task_id,
        "repo_slug": repo_slug,
        "sha": sha,
        "parent_sha": parent_sha,
        "language": language,
        "agents": commit_info.get("agents", []),
        "commit_message": commit_info.get("commit_message", ""),
        "changed_files": commit_info.get("changed_files", []),
        "vuln_files": vuln_files,
        "vuln_types": vuln_types,
        "true_positives": summary.get("true_positives", 0),
        "diff": diff,
        "file_contents": file_contents,
        "prompt": None,
    }


def select_pilot(tasks: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    """Select a diverse pilot set of tasks.

    Strategy: ensure coverage of vuln types, languages, and agents,
    preferring single-vuln-file commits.
    """
    if len(tasks) <= limit:
        return tasks

    selected = []
    selected_ids = set()

    # Phase 1: Ensure at least one of each vuln type
    type_covered = set()
    for task in tasks:
        for vt in task["vuln_types"]:
            if vt not in type_covered:
                if task["task_id"] not in selected_ids:
                    selected.append(task)
                    selected_ids.add(task["task_id"])
                    type_covered.update(task["vuln_types"])
                    break
        if len(selected) >= limit:
            return selected[:limit]

    # Phase 2: Ensure language coverage
    lang_covered = {t["language"] for t in selected}
    for task in tasks:
        if task["language"] not in lang_covered and task["task_id"] not in selected_ids:
            selected.append(task)
            selected_ids.add(task["task_id"])
            lang_covered.add(task["language"])
        if len(selected) >= limit:
            return selected[:limit]

    # Phase 3: Ensure agent coverage
    agent_covered = set()
    for t in selected:
        agent_covered.update(t["agents"])
    for task in tasks:
        task_agents = set(task["agents"])
        if not task_agents.issubset(agent_covered) and task["task_id"] not in selected_ids:
            selected.append(task)
            selected_ids.add(task["task_id"])
            agent_covered.update(task_agents)
        if len(selected) >= limit:
            return selected[:limit]

    # Phase 4: Fill remaining with single-vuln-file commits first
    single_file = [t for t in tasks if len(t["vuln_files"]) == 1 and t["task_id"] not in selected_ids]
    multi_file = [t for t in tasks if len(t["vuln_files"]) > 1 and t["task_id"] not in selected_ids]

    for task in single_file + multi_file:
        if len(selected) >= limit:
            break
        selected.append(task)
        selected_ids.add(task["task_id"])

    return selected[:limit]


def main() -> None:
    load_env()

    ap = argparse.ArgumentParser(description="Build tasks.jsonl from Vulnhalla TP data")
    ap.add_argument("--db-root", type=Path, default=DB_ROOT,
                     help="Root directory with repo/sha/vulnhalla_summary.json")
    ap.add_argument("--workspace-root", type=Path, default=WORKSPACE_ROOT,
                     help="Root directory with cloned repos")
    ap.add_argument("--output", type=Path,
                     default=Path(__file__).parent / "tasks.jsonl",
                     help="Output JSONL file")
    ap.add_argument("--limit", type=int, default=0,
                     help="Limit to N tasks (0 = all). Uses diversity selection.")
    ap.add_argument("--min-tp", type=int, default=1,
                     help="Minimum true positives per commit")
    ap.add_argument("--language", type=str, default="",
                     help="Comma-separated language filter (e.g., javascript,python)")
    ap.add_argument("--dry-run", action="store_true",
                     help="Print stats without writing output")
    args = ap.parse_args()

    db_root = args.db_root.resolve()
    workspace_root = args.workspace_root.resolve()

    print(f"Scanning {db_root} for TP commits (min_tp={args.min_tp})...", file=sys.stderr)
    entries = find_tp_commits(db_root, args.min_tp)
    print(f"Found {len(entries)} commits with >= {args.min_tp} true positives.", file=sys.stderr)

    # Build task records
    tasks = []
    skipped = Counter()
    for entry in entries:
        task = build_task_record(entry, workspace_root)
        if task is None:
            skipped["no_parent_or_workspace"] += 1
            continue
        if not task["diff"]:
            skipped["no_diff"] += 1
            continue
        tasks.append(task)

    print(f"Built {len(tasks)} task records. Skipped: {dict(skipped)}", file=sys.stderr)

    # Apply language filter
    if args.language:
        langs = {l.strip().lower() for l in args.language.split(",")}
        before = len(tasks)
        tasks = [t for t in tasks if t["language"] in langs]
        print(f"Language filter ({args.language}): {before} -> {len(tasks)}", file=sys.stderr)

    # Apply limit with diversity selection
    if args.limit > 0:
        tasks = select_pilot(tasks, args.limit)
        print(f"Selected {len(tasks)} tasks (limit={args.limit})", file=sys.stderr)

    # Print stats
    lang_counts = Counter(t["language"] for t in tasks)
    agent_counts = Counter(a for t in tasks for a in t["agents"])
    vuln_counts = Counter(v for t in tasks for v in t["vuln_types"])
    single_file = sum(1 for t in tasks if len(t["vuln_files"]) == 1)

    print(f"\n--- Task Statistics ---", file=sys.stderr)
    print(f"Total tasks: {len(tasks)}", file=sys.stderr)
    print(f"Single-vuln-file: {single_file} ({100*single_file/max(len(tasks),1):.0f}%)", file=sys.stderr)
    print(f"\nLanguages:", file=sys.stderr)
    for lang, cnt in lang_counts.most_common():
        print(f"  {lang}: {cnt}", file=sys.stderr)
    print(f"\nAgents:", file=sys.stderr)
    for agent, cnt in agent_counts.most_common():
        print(f"  {agent}: {cnt}", file=sys.stderr)
    print(f"\nVuln types (top 15):", file=sys.stderr)
    for vtype, cnt in vuln_counts.most_common(15):
        print(f"  {vtype}: {cnt}", file=sys.stderr)

    if args.dry_run:
        print("\n[dry-run] Not writing output.", file=sys.stderr)
        return

    # Write JSONL
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for task in tasks:
            f.write(json.dumps(task, ensure_ascii=False) + "\n")

    print(f"\nWrote {len(tasks)} tasks to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
