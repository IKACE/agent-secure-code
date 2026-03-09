#!/usr/bin/env python3
"""
Two-phase pipeline: CodeQL DB creation + query execution → Vulnhalla LLM classification.

Phase 1 (parallelizable, CPU-bound):
    - Create CodeQL databases (if not already done)
    - Run CodeQL security-extended query suite on each DB
    - Run tool queries (FunctionTree, Classes, etc.)
    → Produces issues.csv + tool CSVs in each DB directory

Phase 2 (rate-limited, sequential or lightly parallel):
    - Run Vulnhalla LLM classification only on DBs that have issues
    → Produces vulnhalla_summary.json per commit

Usage:
    # Phase 1 only (create DBs + run queries, no LLM):
    python run_pipeline.py --crawl-dir ... --output-dir ... --query-jobs 16

    # Phase 2 only (LLM on existing query results):
    python run_pipeline.py --crawl-dir ... --output-dir ... --skip-queries --llm-jobs 2

    # Both phases:
    python run_pipeline.py --crawl-dir ... --output-dir ... --query-jobs 16 --llm-jobs 2
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Import shared functions from the individual scripts
from create_codeql_dbs import (
    slug, iter_commits, process_one_commit, round_robin_by_repo,
    LANGUAGES_BUILD_NONE, LANGUAGES_AUTOBUILD,
)
from run_vulnhalla_batch import (
    CODEQL_TO_VULNHALLA, map_to_vulnhalla_lang,
    run_vulnhalla_headless, copy_vulnhalla_results,
)
from summarize_results import collect_results, build_summary, write_csv


# ---------------------------------------------------------------------------
# Phase 1 helpers: CodeQL query execution (no LLM, fully parallelizable)
# ---------------------------------------------------------------------------

def _resolve_security_suite(codeql_bin: str, github_lang: str) -> Optional[str]:
    """Find the security-extended.qls suite in the CodeQL distribution."""
    codeql_path = Path(codeql_bin).resolve()
    dist_root = codeql_path.parent if codeql_path.exists() else None
    if dist_root is None:
        return None
    qlpacks = dist_root / "qlpacks"
    if not qlpacks.exists():
        return None
    suite_name = f"{github_lang}-security-extended.qls"
    for match in qlpacks.rglob(f"**/codeql-suites/{suite_name}"):
        return str(match)
    return None


# Vulnhalla lang → CodeQL github lang mapping
VH_TO_GITHUB_LANG = {"c": "cpp", "python": "python", "javascript": "javascript"}
# Vulnhalla lang → query subfolder
VH_TO_QUERY_DIR = {"c": "cpp", "python": "python", "javascript": "javascript"}


def run_codeql_queries_on_db(
    db_path: Path,
    vulnhalla_lang: str,
    codeql_bin: str,
    vulnhalla_dir: Path,
    threads: int = 4,
    timeout: int = 300,
) -> Tuple[bool, int, str]:
    """
    Run CodeQL tool queries + security suite on a single DB.
    Returns (success, issue_count, error_message).
    This is the CPU-bound step that can be parallelized.
    """
    if not db_path.is_dir():
        return False, 0, f"DB path not found: {db_path}"

    # Skip if already done
    issues_csv = db_path / "issues.csv"
    func_tree = db_path / "FunctionTree.csv"
    if issues_csv.exists() and func_tree.exists():
        # Count existing issues
        count = _count_issues(issues_csv)
        return True, count, "already_done"

    github_lang = VH_TO_GITHUB_LANG.get(vulnhalla_lang, vulnhalla_lang)
    query_dir = VH_TO_QUERY_DIR.get(vulnhalla_lang, vulnhalla_lang)

    # Paths to Vulnhalla query folders
    tools_folder = vulnhalla_dir / "data" / "queries" / query_dir / "tools"
    queries_folder = vulnhalla_dir / "data" / "queries" / query_dir / "issues"

    # 1) Run tool queries (FunctionTree, Classes, GlobalVars, Imports)
    if tools_folder.is_dir():
        for ql_file in sorted(tools_folder.iterdir()):
            if ql_file.suffix.lower() != ".ql":
                continue
            stem = ql_file.stem
            bqrs_path = db_path / f"{stem}.bqrs"
            csv_path = db_path / f"{stem}.csv"
            try:
                subprocess.run(
                    [codeql_bin, "query", "run",
                     "-d", str(db_path),
                     "-o", str(bqrs_path),
                     f"--threads={threads}",
                     str(ql_file)],
                    capture_output=True, text=True, timeout=timeout,
                    check=True,
                )
                subprocess.run(
                    [codeql_bin, "bqrs", "decode",
                     "--format=csv",
                     f"--output={csv_path}",
                     str(bqrs_path)],
                    capture_output=True, text=True, timeout=60,
                    check=True,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                # Tool query failures are non-fatal
                pass

    # 2) Run security suite (or fallback to custom queries)
    security_suite = _resolve_security_suite(codeql_bin, github_lang)
    analyze_target = security_suite if security_suite else str(queries_folder)

    try:
        subprocess.run(
            [codeql_bin, "database", "analyze",
             str(db_path),
             analyze_target,
             f"--timeout={timeout}",
             "--format=csv",
             f"--output={str(issues_csv)}",
             f"--threads={threads}"],
            capture_output=True, text=True, timeout=timeout * 3,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        return False, 0, f"codeql analyze failed (exit {e.returncode}): {(e.stderr or '')[-300:]}"
    except subprocess.TimeoutExpired:
        return False, 0, "codeql analyze timed out"

    count = _count_issues(issues_csv)
    return True, count, ""


def _count_issues(issues_csv: Path) -> int:
    """Count rows in issues.csv (CodeQL CSV has no header row)."""
    if not issues_csv.exists():
        return 0
    try:
        with issues_csv.open(encoding="utf-8") as f:
            reader = csv.reader(f)
            return sum(1 for _ in reader)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Phase 1: Collect all DB items and run queries in parallel
# ---------------------------------------------------------------------------

def collect_db_items(
    commits: List[Dict[str, Any]],
    output_dir: Path,
    vh_lang_filter: Optional[Set[str]],
) -> List[Dict[str, Any]]:
    """
    Scan all commits and collect DB items that need query execution.
    Reads commit_info.json to find successful DBs.
    """
    items = []
    for commit in commits:
        repo_full = commit["repo"]
        sha = commit["sha"]
        commit_out = output_dir / slug(repo_full) / sha
        info_path = commit_out / "commit_info.json"
        if not info_path.exists():
            continue
        try:
            info = json.loads(info_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for lang, res in info.get("db_results", {}).items():
            if not res.get("success"):
                continue
            db_path = commit_out / "db" / lang
            if not db_path.is_dir():
                continue
            vh_lang = map_to_vulnhalla_lang(lang)
            if vh_lang is None:
                continue
            if vh_lang_filter and vh_lang not in vh_lang_filter:
                continue
            items.append({
                "repo_slug": slug(repo_full),
                "repo_full": repo_full,
                "sha": sha,
                "codeql_lang": lang,
                "vulnhalla_lang": vh_lang,
                "db_path": db_path,
                "commit_dir": commit_out,
                "agents": commit.get("agents", []),
            })
    return items


def run_queries_phase(
    items: List[Dict[str, Any]],
    codeql_bin: str,
    vulnhalla_dir: Path,
    query_jobs: int,
    codeql_threads: int,
    query_timeout: int,
    errors_jsonl: Path,
) -> Dict[str, int]:
    """
    Phase 1: Run CodeQL queries on all DB items in parallel.
    Returns stats dict.
    """
    stats = {"total": len(items), "done": 0, "skipped": 0, "issues_found": 0, "errors": 0}
    stats_lock = threading.Lock()

    def _run_one(item: Dict[str, Any]) -> None:
        db_path = item["db_path"]
        repo_slug = item["repo_slug"]
        sha = item["sha"]
        vh_lang = item["vulnhalla_lang"]

        success, issue_count, err_msg = run_codeql_queries_on_db(
            db_path, vh_lang, codeql_bin, vulnhalla_dir,
            threads=codeql_threads, timeout=query_timeout,
        )

        with stats_lock:
            stats["done"] += 1
            n = stats["done"]
            if err_msg == "already_done":
                stats["skipped"] += 1
            if success:
                stats["issues_found"] += issue_count
            else:
                stats["errors"] += 1

        status = "ok" if success else "FAIL"
        extra = f" issues={issue_count}" if success else f" {err_msg[:80]}"
        if err_msg == "already_done":
            status = "skip"
        print(
            f"[Q {n}/{len(items)}] {status} {repo_slug} {sha[:10]} {vh_lang}{extra}",
            file=sys.stderr, flush=True,
        )

        if not success:
            error_record = {
                "stage": "codeql_query",
                "repo_slug": repo_slug,
                "sha": sha,
                "language": vh_lang,
                "error": err_msg,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
            with stats_lock:
                with errors_jsonl.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(error_record, ensure_ascii=False) + "\n")

    print(
        f"\n{'='*60}\n"
        f"Phase 1: Running CodeQL queries on {len(items)} DBs "
        f"({query_jobs} parallel workers, {codeql_threads} threads each)\n"
        f"{'='*60}",
        file=sys.stderr, flush=True,
    )
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=query_jobs) as pool:
        futures = [pool.submit(_run_one, item) for item in items]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as exc:
                print(f"[Q] unexpected error: {exc}", file=sys.stderr, flush=True)

    elapsed = time.time() - t0
    print(
        f"\nPhase 1 complete in {elapsed:.0f}s. "
        f"Processed: {stats['done']}/{stats['total']}, "
        f"Skipped: {stats['skipped']}, "
        f"Issues found: {stats['issues_found']}, "
        f"Errors: {stats['errors']}",
        file=sys.stderr, flush=True,
    )
    return stats


# ---------------------------------------------------------------------------
# Phase 1.5: Filter issues to commit scope
# ---------------------------------------------------------------------------

def get_changed_line_ranges(
    workspace: Path,
    repo_slug: str,
    parent_sha: str,
    sha: str,
) -> Optional[Dict[str, List[Tuple[int, int]]]]:
    """
    Compute changed line ranges using git diff parent..sha --unified=0.
    Returns dict mapping file path (relative to repo root, no leading /)
    to list of (start_line, end_line) ranges in the NEW file.
    Returns None if git diff fails.
    """
    repo_dir = workspace / repo_slug
    if not repo_dir.is_dir():
        return None
    try:
        r = subprocess.run(
            ["git", "diff", f"{parent_sha}..{sha}", "--unified=0", "--no-color"],
            cwd=str(repo_dir),
            capture_output=True, timeout=60,
        )
        if r.returncode != 0:
            return None
        diff_text = r.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    ranges: Dict[str, List[Tuple[int, int]]] = {}
    current_file: Optional[str] = None

    for line in diff_text.splitlines():
        # New file: +++ b/path/to/file
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@ ") and current_file is not None:
            # @@ -old_start,old_count +new_start,new_count @@
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if m:
                new_start = int(m.group(1))
                new_count = int(m.group(2)) if m.group(2) else 1
                if new_count > 0:  # skip pure deletions
                    new_end = new_start + new_count - 1
                    ranges.setdefault(current_file, []).append((new_start, new_end))
    return ranges


def filter_issues_to_commit_scope(
    issues_csv: Path,
    changed_files: List[str],
    changed_ranges: Optional[Dict[str, List[Tuple[int, int]]]],
) -> Tuple[int, int]:
    """
    Filter issues.csv to only include issues in files/lines changed by the commit.

    - Saves original as issues_all.csv (idempotent)
    - Overwrites issues.csv with filtered version
    Returns (original_count, filtered_count).
    """
    backup = issues_csv.parent / "issues_all.csv"
    # Always read from backup (unfiltered) if it exists, to make re-runs idempotent
    source = backup if backup.exists() else issues_csv

    if not source.exists():
        return 0, 0

    # Read all rows from source
    rows: List[List[str]] = []
    try:
        with source.open(encoding="utf-8") as f:
            rows = list(csv.reader(f))
    except Exception:
        return 0, 0

    original_count = len(rows)
    if original_count == 0:
        return 0, 0

    # Back up original (only once)
    if not backup.exists():
        shutil.copy2(issues_csv, backup)

    # Normalize changed_files for comparison
    changed_set = {cf.lstrip("/") for cf in changed_files}

    # Filter rows
    filtered: List[List[str]] = []
    for row in rows:
        if len(row) < 8:
            continue
        file_path = row[4]
        try:
            issue_start = int(row[5])
            issue_end = int(row[7])
        except (ValueError, IndexError):
            continue

        # Normalize: issues.csv paths have leading /, changed_files don't
        norm_path = file_path.lstrip("/")

        # Step 1: File must be in the set of changed files
        if norm_path not in changed_set:
            continue

        # Step 2: If line-level ranges available, check overlap
        if changed_ranges is not None:
            file_ranges = changed_ranges.get(norm_path)
            if file_ranges is None:
                continue
            # Two ranges [a,b] and [c,d] overlap iff a <= d AND c <= b
            if not any(a <= issue_end and issue_start <= b for a, b in file_ranges):
                continue

        filtered.append(row)

    # Write filtered issues.csv
    with issues_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(filtered)

    return original_count, len(filtered)


def run_filter_phase(
    items: List[Dict[str, Any]],
    workspace: Path,
) -> Dict[str, int]:
    """
    Phase 1.5: Filter issues.csv to only include commit-scoped vulnerabilities.
    Runs between Phase 1 (CodeQL queries) and Phase 2 (Vulnhalla LLM).
    """
    stats = {
        "total": len(items), "filtered": 0,
        "original_issues": 0, "filtered_issues": 0,
        "no_overlap": 0, "no_diff": 0, "errors": 0,
    }

    print(
        f"\n{'='*60}\n"
        f"Phase 1.5: Filtering issues to commit scope ({len(items)} DBs)\n"
        f"{'='*60}",
        file=sys.stderr, flush=True,
    )

    for idx, item in enumerate(items, start=1):
        commit_dir = item["commit_dir"]
        db_path = item["db_path"]
        repo_slug = item["repo_slug"]
        sha = item["sha"]
        issues_csv = db_path / "issues.csv"

        if not issues_csv.exists() and not (db_path / "issues_all.csv").exists():
            continue

        # Read commit info for changed_files and parent_sha
        info_path = commit_dir / "commit_info.json"
        try:
            info = json.loads(info_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            stats["errors"] += 1
            continue

        changed_files = info.get("changed_files", [])
        parent_sha = info.get("parent_sha", "")

        if not changed_files:
            stats["errors"] += 1
            continue

        # Get line-level changed ranges from git diff
        changed_ranges = None
        if parent_sha:
            changed_ranges = get_changed_line_ranges(
                workspace, repo_slug, parent_sha, sha,
            )
            if changed_ranges is None:
                stats["no_diff"] += 1

        orig, filt = filter_issues_to_commit_scope(
            issues_csv, changed_files, changed_ranges,
        )

        stats["original_issues"] += orig
        stats["filtered_issues"] += filt
        stats["filtered"] += 1

        if filt == 0 and orig > 0:
            stats["no_overlap"] += 1

        print(
            f"[F {idx}/{len(items)}] {repo_slug} {sha[:10]} "
            f"issues: {orig} → {filt}"
            f"{' (no diff available, file-level only)' if changed_ranges is None and filt > 0 else ''}",
            file=sys.stderr, flush=True,
        )

    print(
        f"\nPhase 1.5 complete. "
        f"Original issues: {stats['original_issues']}, "
        f"After filter: {stats['filtered_issues']} "
        f"({stats['no_overlap']} DBs had zero commit-scoped issues, "
        f"{stats['no_diff']} couldn't compute git diff)",
        file=sys.stderr, flush=True,
    )
    return stats


# ---------------------------------------------------------------------------
# Phase 2: LLM classification via Vulnhalla (rate-limited)
# ---------------------------------------------------------------------------

def run_llm_phase(
    items: List[Dict[str, Any]],
    vulnhalla_dir: Path,
    llm_jobs: int,
    vulnhalla_timeout: int,
    errors_jsonl: Path,
) -> Dict[str, int]:
    """
    Phase 2: Run Vulnhalla LLM classification on DBs that have issues.
    Only processes DBs where issues.csv has >0 rows.
    """
    # Filter to only DBs with issues
    items_with_issues = []
    for item in items:
        issues_csv = item["db_path"] / "issues.csv"
        count = _count_issues(issues_csv)
        if count > 0:
            # Skip if already classified
            summary_path = item["commit_dir"] / "vulnhalla_summary.json"
            if summary_path.exists():
                continue
            item["issue_count"] = count
            items_with_issues.append(item)

    if not items_with_issues:
        print("\nPhase 2: No issues to classify with LLM.", file=sys.stderr, flush=True)
        return {"total": 0, "done": 0, "errors": 0}

    print(
        f"\n{'='*60}\n"
        f"Phase 2: LLM classification on {len(items_with_issues)} DBs with issues "
        f"({llm_jobs} parallel workers)\n"
        f"{'='*60}",
        file=sys.stderr, flush=True,
    )

    stats = {"total": len(items_with_issues), "done": 0, "errors": 0,
             "true_positives": 0, "false_positives": 0}
    stats_lock = threading.Lock()
    t0 = time.time()

    def _run_one_llm(item: Dict[str, Any]) -> None:
        repo_slug = item["repo_slug"]
        sha = item["sha"]
        vh_lang = item["vulnhalla_lang"]
        db_path = item["db_path"]
        commit_dir = item["commit_dir"]

        with stats_lock:
            stats["done"] += 1
            n = stats["done"]

        print(
            f"[LLM {n}/{len(items_with_issues)}] start {repo_slug} {sha[:10]} "
            f"{vh_lang} ({item.get('issue_count', '?')} issues)",
            file=sys.stderr, flush=True,
        )

        start = time.time()
        success, err_msg = run_vulnhalla_headless(
            db_path, vh_lang, vulnhalla_dir, vulnhalla_timeout,
        )
        elapsed = time.time() - start

        if success:
            summary = copy_vulnhalla_results(vulnhalla_dir, vh_lang, commit_dir)
            summary["repo_slug"] = repo_slug
            summary["sha"] = sha
            summary["language"] = vh_lang
            summary["elapsed_seconds"] = round(elapsed, 1)
            summary["ts"] = datetime.now(timezone.utc).isoformat()
            (commit_dir / "vulnhalla_summary.json").write_text(
                json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            tp = summary.get("true_positives", 0)
            fp = summary.get("false_positives", 0)
            with stats_lock:
                stats["true_positives"] += tp
                stats["false_positives"] += fp
            print(
                f"[LLM {n}] done {repo_slug} {sha[:10]} "
                f"issues={summary.get('total_issues', 0)} "
                f"TP={tp} FP={fp} ({elapsed:.0f}s)",
                file=sys.stderr, flush=True,
            )
        else:
            error_record = {
                "stage": "llm_classify",
                "repo_slug": repo_slug,
                "sha": sha,
                "language": vh_lang,
                "error": err_msg,
                "elapsed_seconds": round(elapsed, 1),
                "ts": datetime.now(timezone.utc).isoformat(),
            }
            (commit_dir / f"vulnhalla_error_{vh_lang}.json").write_text(
                json.dumps(error_record, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            with stats_lock:
                stats["errors"] += 1
                with errors_jsonl.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(error_record, ensure_ascii=False) + "\n")
            print(
                f"[LLM {n}] ERROR {repo_slug} {sha[:10]}: {err_msg[:100]}",
                file=sys.stderr, flush=True,
            )

    # LLM phase: use limited parallelism to respect rate limits
    with ThreadPoolExecutor(max_workers=llm_jobs) as pool:
        futures = [pool.submit(_run_one_llm, item) for item in items_with_issues]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as exc:
                print(f"[LLM] unexpected error: {exc}", file=sys.stderr, flush=True)

    elapsed = time.time() - t0
    print(
        f"\nPhase 2 complete in {elapsed:.0f}s. "
        f"Classified: {stats['done']}/{stats['total']}, "
        f"TP: {stats['true_positives']}, FP: {stats['false_positives']}, "
        f"Errors: {stats['errors']}",
        file=sys.stderr, flush=True,
    )
    return stats


# ---------------------------------------------------------------------------
# DB creation phase (reuses existing producer logic)
# ---------------------------------------------------------------------------

def run_db_creation_phase(
    todo: List[Dict[str, Any]],
    workspace: Path,
    output_dir: Path,
    codeql_bin: str,
    lang_filter: Optional[Set[str]],
    db_timeout: int,
    db_jobs: int,
    errors_jsonl: Path,
) -> None:
    """Create CodeQL DBs for commits that don't have them yet."""
    # Filter to commits that actually need DB creation
    need_db = [
        c for c in todo
        if not (output_dir / slug(c["repo"]) / c["sha"] / "commit_info.json").exists()
    ]
    if not need_db:
        print(f"All {len(todo)} commits already have DBs.", file=sys.stderr, flush=True)
        return

    if db_jobs > 1:
        need_db = round_robin_by_repo(need_db)

    # Build repo locks
    repo_locks: Dict[str, threading.Lock] = {}
    for c in need_db:
        rs = slug(c["repo"])
        if rs not in repo_locks:
            repo_locks[rs] = threading.Lock()

    total = len(need_db)
    print(
        f"\n{'='*60}\n"
        f"DB Creation: {total} commits need databases ({db_jobs} workers)\n"
        f"{'='*60}",
        file=sys.stderr, flush=True,
    )

    progress = {"done": 0}
    progress_lock = threading.Lock()

    def _create_one(commit: Dict[str, Any]) -> None:
        repo_full = commit["repo"]
        sha = commit["sha"]
        with repo_locks[slug(repo_full)]:
            result = process_one_commit(
                commit, workspace, output_dir,
                codeql_bin, lang_filter, db_timeout,
            )
        with progress_lock:
            progress["done"] += 1
            n = progress["done"]
        status = result.get("status", "?")
        extra = ""
        if status == "done":
            extra = f" dbs={result.get('successful_dbs', [])}"
        elif status == "error":
            extra = f" err={result.get('error', '?')}"
        print(f"[DB {n}/{total}] {status} {repo_full} {sha[:10]}{extra}",
              file=sys.stderr, flush=True)
        if result.get("status") == "error":
            with progress_lock:
                with errors_jsonl.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(result, ensure_ascii=False) + "\n")

    with ThreadPoolExecutor(max_workers=db_jobs) as pool:
        futures = [pool.submit(_create_one, c) for c in need_db]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as exc:
                print(f"[DB] unexpected error: {exc}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Two-phase pipeline: CodeQL queries (parallel) → LLM classification (batched)"
    )
    ap.add_argument(
        "--crawl-dir", type=Path,
        default=Path(__file__).resolve().parent.parent.parent
        / "crawled_output_ai_coauthored_all",
        help="Root of crawled data (contains repos/ subdirectory)",
    )
    ap.add_argument(
        "--output-dir", type=Path,
        default=Path(__file__).resolve().parent / "ai_commit_dbs",
        help="Output directory for CodeQL databases and results",
    )
    ap.add_argument(
        "--workspace", type=Path, default=None,
        help="Clone workspace (default: <output-dir>/workspace)",
    )
    ap.add_argument(
        "--codeql", default="/home/yilegu/agent-blockchain-security/codeql/codeql/codeql",
        help="Path to CodeQL CLI binary",
    )
    ap.add_argument(
        "--vulnhalla-dir", type=Path,
        default=Path.home() / "agent-blockchain-security" / "Vulnhalla",
        help="Path to Vulnhalla installation directory",
    )
    ap.add_argument("--repo", type=str, default=None, help="Limit to one repo (owner/name)")
    ap.add_argument("--sha", type=str, default=None, help="Limit to one commit SHA")
    ap.add_argument(
        "--languages", type=str, default=None,
        help="Comma-separated CodeQL language filter for DB creation (e.g. python,javascript,cpp)",
    )
    ap.add_argument(
        "--vulnhalla-languages", type=str, default=None,
        help="Comma-separated Vulnhalla language filter (e.g. c,python,javascript). "
             "Only DBs matching these will be queried and classified.",
    )

    # Phase control
    ap.add_argument("--db-jobs", type=int, default=4,
                    help="Parallel workers for CodeQL DB creation (default 4)")
    ap.add_argument("--db-timeout", type=int, default=600,
                    help="Timeout for CodeQL DB creation in seconds (default 600)")
    ap.add_argument("--query-jobs", type=int, default=8,
                    help="Parallel workers for CodeQL query execution (default 8)")
    ap.add_argument("--codeql-threads", type=int, default=4,
                    help="Threads per CodeQL query worker (default 4)")
    ap.add_argument("--query-timeout", type=int, default=300,
                    help="Timeout for CodeQL query execution in seconds (default 300)")
    ap.add_argument("--llm-jobs", type=int, default=1,
                    help="Parallel workers for LLM classification (default 1, be careful with rate limits)")
    ap.add_argument("--vulnhalla-timeout", type=int, default=1800,
                    help="Timeout for Vulnhalla LLM analysis in seconds (default 1800)")

    # Skip flags
    ap.add_argument("--skip-db-creation", action="store_true",
                    help="Skip DB creation (assumes DBs already exist)")
    ap.add_argument("--skip-queries", action="store_true",
                    help="Skip CodeQL query execution (assumes issues.csv already exist)")
    ap.add_argument("--skip-filter", action="store_true",
                    help="Skip commit-scope filtering (analyze entire repo, not just changed lines)")
    ap.add_argument("--skip-llm", action="store_true",
                    help="Skip LLM classification (only run CodeQL queries)")
    ap.add_argument("--skip-summary", action="store_true",
                    help="Skip final summary generation")
    ap.add_argument("--list-only", action="store_true", help="Only list commits and exit")
    args = ap.parse_args()

    crawl_dir = args.crawl_dir.resolve()
    output_dir = args.output_dir.resolve()
    workspace = (args.workspace or output_dir / "workspace").resolve()
    vulnhalla_dir = args.vulnhalla_dir.resolve()
    lang_filter: Optional[Set[str]] = None
    if args.languages:
        lang_filter = set(args.languages.split(","))
    vh_lang_filter: Optional[Set[str]] = None
    if args.vulnhalla_languages:
        vh_lang_filter = set(args.vulnhalla_languages.split(","))

    # Gather all commits
    commits = iter_commits(crawl_dir, args.repo, args.sha)
    print(f"Found {len(commits)} commits total.", file=sys.stderr)

    if args.list_only:
        for c in commits:
            print(f"{c['repo']}\t{c['sha']}\t{','.join(c.get('agents', []))}")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)
    errors_jsonl = output_dir / "errors.jsonl"

    pipeline_start = time.time()

    # --- DB Creation Phase ---
    if not args.skip_db_creation:
        run_db_creation_phase(
            commits, workspace, output_dir, args.codeql,
            lang_filter, args.db_timeout, args.db_jobs, errors_jsonl,
        )

    # --- Collect all DB items for query + LLM phases ---
    all_items = collect_db_items(commits, output_dir, vh_lang_filter)
    print(f"\nFound {len(all_items)} DB items for analysis.", file=sys.stderr, flush=True)

    if not all_items:
        print("No DB items found. Check DB creation results.", file=sys.stderr)
        if not args.skip_summary:
            _run_summary(output_dir)
        return

    # --- Phase 1: CodeQL Queries (parallel) ---
    if not args.skip_queries:
        run_queries_phase(
            all_items, args.codeql, vulnhalla_dir,
            args.query_jobs, args.codeql_threads, args.query_timeout,
            errors_jsonl,
        )

    # --- Phase 1.5: Filter issues to commit scope ---
    if not args.skip_filter:
        run_filter_phase(all_items, workspace)

    # --- Phase 2: LLM Classification (controlled parallelism) ---
    if not args.skip_llm:
        run_llm_phase(
            all_items, vulnhalla_dir, args.llm_jobs,
            args.vulnhalla_timeout, errors_jsonl,
        )

    elapsed = time.time() - pipeline_start
    print(f"\nTotal pipeline time: {elapsed:.0f}s", file=sys.stderr)

    # --- Summary ---
    if not args.skip_summary:
        _run_summary(output_dir)


def _run_summary(output_dir: Path) -> None:
    """Generate summary JSON and CSV."""
    print("\nGenerating summary...", file=sys.stderr)
    results = collect_results(output_dir)
    if not results:
        print("No results to summarize.", file=sys.stderr)
        return

    summary = build_summary(results)
    script_dir = Path(__file__).resolve().parent

    json_path = script_dir / "ai_commit_vulnerability_summary.json"
    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    csv_path = script_dir / "ai_commit_vulnerability_summary.csv"
    write_csv(summary["findings"], csv_path)

    print(f"Summary: {summary['total_commits_analyzed']} commits analyzed, "
          f"{summary['total_issues_found']} issues, "
          f"{summary['total_true_positives']} TP, "
          f"{summary['total_false_positives']} FP",
          file=sys.stderr)
    print(f"JSON: {json_path}", file=sys.stderr)
    print(f"CSV:  {csv_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
