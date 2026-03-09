#!/usr/bin/env python3
"""
Script 1: Create CodeQL databases from AI-assisted commits.

Reads crawled data from crawled_output_ai_coauthored_all/repos/<repo_slug>/commits.jsonl,
clones each repo, checks out each AI commit, detects languages from the repo tree,
and creates per-language CodeQL databases.

Output structure per commit:
    <output_dir>/<repo_slug>/<sha>/
        db/<lang>/              CodeQL database
        commit_info.json        Commit metadata + detected languages + changed files
        error.json              (if DB creation failed)

Usage:
    python create_codeql_dbs.py \
        --crawl-dir /path/to/crawled_output_ai_coauthored_all \
        --output-dir ./ai_commit_dbs \
        --codeql /path/to/codeql \
        --jobs 4
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def slug(repo_full: str) -> str:
    """Convert 'owner/repo' to 'owner__repo' for filesystem use."""
    return repo_full.replace("/", "__")


# Extension → CodeQL language mapping
EXT_TO_LANG: Dict[str, str] = {}
for _ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
    EXT_TO_LANG[_ext] = "javascript"
EXT_TO_LANG[".py"] = "python"
EXT_TO_LANG[".go"] = "go"
for _ext in (".java", ".kt"):
    EXT_TO_LANG[_ext] = "java"
for _ext in (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"):
    EXT_TO_LANG[_ext] = "cpp"
EXT_TO_LANG[".rb"] = "ruby"
EXT_TO_LANG[".cs"] = "csharp"

# Languages that can be analyzed without a build step
LANGUAGES_BUILD_NONE = frozenset({"javascript", "python", "ruby", "csharp", "java", "cpp"})
# Languages that require autobuild (skip unless build system detected)
LANGUAGES_AUTOBUILD = frozenset({"go", "swift"})


# ---------------------------------------------------------------------------
# Git operations
# ---------------------------------------------------------------------------

def git_clone(repo_full: str, dest: Path, repo_url: Optional[str] = None) -> bool:
    """Clone a repo (full clone, no shallow). Returns True on success (or if already cloned)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return True
    url = repo_url or f"https://github.com/{repo_full}.git"
    try:
        r = subprocess.run(
            ["git", "clone", url, str(dest)],
            capture_output=True, text=True, timeout=1200,
        )
        if r.returncode != 0:
            print(f"[clone] {repo_full} failed: {r.stderr.strip()[:200]}", file=sys.stderr)
        return dest.exists()
    except subprocess.TimeoutExpired:
        print(f"[clone] {repo_full} timed out", file=sys.stderr)
        return False
    except FileNotFoundError:
        return False


def ensure_commit(repo_dir: Path, sha: str) -> bool:
    """Ensure a commit is available (try unshallow if needed)."""
    r = subprocess.run(
        ["git", "rev-parse", "--verify", f"{sha}^{{commit}}"],
        cwd=repo_dir, capture_output=True, text=True, timeout=10,
    )
    if r.returncode == 0:
        return True
    try:
        subprocess.run(
            ["git", "fetch", "origin", "--unshallow"],
            cwd=repo_dir, capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        return False
    r = subprocess.run(
        ["git", "rev-parse", "--verify", f"{sha}^{{commit}}"],
        cwd=repo_dir, capture_output=True, text=True, timeout=10,
    )
    return r.returncode == 0


def git_checkout(repo_dir: Path, ref: str) -> bool:
    """Force-checkout a ref."""
    try:
        subprocess.run(
            ["git", "checkout", "--force", ref],
            cwd=repo_dir, check=True, capture_output=True, timeout=30,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_parent_sha(repo_dir: Path, sha: str) -> Optional[str]:
    """Get the parent commit SHA."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", f"{sha}^"],
            cwd=repo_dir, capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() if r.returncode == 0 and r.stdout else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def get_changed_files(repo_dir: Path, parent_sha: str, sha: str) -> List[str]:
    """Get list of files changed between parent and commit."""
    try:
        r = subprocess.run(
            ["git", "diff", "--name-only", f"{parent_sha}..{sha}"],
            cwd=repo_dir, capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            return [f for f in r.stdout.strip().split("\n") if f]
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

def detect_languages_from_tree(repo_dir: Path, sha: str) -> Set[str]:
    """Detect languages by walking the repo tree at the given commit."""
    try:
        r = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", sha],
            cwd=repo_dir, capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            return set()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return set()

    langs: Set[str] = set()
    for filepath in r.stdout.split("\n"):
        filepath = filepath.strip()
        if not filepath:
            continue
        _, ext = os.path.splitext(filepath.lower())
        if ext in EXT_TO_LANG:
            langs.add(EXT_TO_LANG[ext])
    return langs


def detect_build_system(repo_dir: Path) -> bool:
    """Check if repo has common build system files (Makefile, CMakeLists.txt, etc.)."""
    build_files = [
        "Makefile", "makefile", "CMakeLists.txt", "configure",
        "configure.ac", "meson.build", "build.gradle", "pom.xml",
        "go.mod", "Cargo.toml",
    ]
    for bf in build_files:
        if (repo_dir / bf).exists():
            return True
    return False


# ---------------------------------------------------------------------------
# CodeQL database creation
# ---------------------------------------------------------------------------

def create_codeql_db(
    codeql_bin: str,
    repo_dir: Path,
    db_path: Path,
    language: str,
    timeout_seconds: int = 600,
) -> Tuple[bool, str]:
    """
    Create a single-language CodeQL database.
    Returns (success, error_message).
    """
    cmd = [
        codeql_bin, "database", "create",
        "--source-root", str(repo_dir),
        "--overwrite",
        "--language", language,
    ]
    if language in LANGUAGES_BUILD_NONE:
        cmd.append("--build-mode=none")
    # For autobuild languages, let CodeQL auto-detect the build
    cmd.append(str(db_path))

    try:
        r = subprocess.run(
            cmd, cwd=repo_dir,
            capture_output=True, text=True, timeout=timeout_seconds,
        )
        if r.returncode != 0:
            return False, f"codeql exit {r.returncode}: {r.stderr[:500]}"
        # Verify DB was actually created
        if not (db_path / "codeql-database.yml").exists():
            return False, "codeql-database.yml not found after creation"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "codeql database create timed out"
    except FileNotFoundError:
        return False, f"codeql binary not found: {codeql_bin}"


# ---------------------------------------------------------------------------
# Commit iteration
# ---------------------------------------------------------------------------

def iter_commits(crawl_dir: Path, repo_filter: Optional[str] = None,
                 sha_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Iterate over all commits in the crawled data.
    Returns list of commit dicts with keys: repo, sha, agents, html_url, commit_message, ...
    """
    repos_dir = crawl_dir / "repos"
    if not repos_dir.exists():
        print(f"[error] repos dir not found: {repos_dir}", file=sys.stderr)
        return []

    commits = []
    for repo_slug_dir in sorted(repos_dir.iterdir()):
        if not repo_slug_dir.is_dir():
            continue
        commits_file = repo_slug_dir / "commits.jsonl"
        if not commits_file.exists():
            continue

        for line in commits_file.read_text(encoding="utf-8").strip().split("\n"):
            if not line.strip():
                continue
            try:
                commit = json.loads(line)
            except json.JSONDecodeError:
                continue
            repo_full = commit.get("repo", "")
            sha = commit.get("sha", "")
            if not repo_full or not sha:
                continue
            if repo_filter and repo_full != repo_filter:
                continue
            if sha_filter and sha != sha_filter:
                continue
            commits.append(commit)
    return commits


# ---------------------------------------------------------------------------
# Main processing
# ---------------------------------------------------------------------------

def process_one_commit(
    commit: Dict[str, Any],
    workspace: Path,
    output_dir: Path,
    codeql_bin: str,
    lang_filter: Optional[Set[str]] = None,
    db_timeout: int = 600,
) -> Dict[str, Any]:
    """
    Process a single commit: clone, checkout, detect languages, create CodeQL DBs.
    Returns a result dict with status information.
    """
    repo_full = commit["repo"]
    sha = commit["sha"]
    repo_slug_name = slug(repo_full)
    commit_out = output_dir / repo_slug_name / sha

    # Resume support: skip if commit_info.json already exists
    if (commit_out / "commit_info.json").exists():
        return {"status": "skipped", "repo": repo_full, "sha": sha, "reason": "already_done"}

    # Clone repo
    repo_dir = workspace / repo_slug_name
    if not git_clone(repo_full, repo_dir):
        return _error(commit_out, repo_full, sha, "clone_failed",
                      f"Failed to clone {repo_full}")

    # Ensure commit is available
    if not ensure_commit(repo_dir, sha):
        return _error(commit_out, repo_full, sha, "commit_not_found",
                      f"Commit {sha} not found even after unshallow")

    # Get parent SHA and changed files
    parent_sha = get_parent_sha(repo_dir, sha)
    changed_files: List[str] = []
    if parent_sha:
        changed_files = get_changed_files(repo_dir, parent_sha, sha)

    # Checkout the commit
    if not git_checkout(repo_dir, sha):
        return _error(commit_out, repo_full, sha, "checkout_failed",
                      f"Failed to checkout {sha}")

    # Detect languages from repo tree
    detected_langs = detect_languages_from_tree(repo_dir, sha)
    if not detected_langs:
        return _error(commit_out, repo_full, sha, "no_languages_detected",
                      "Could not detect any supported languages in repo tree")

    # Apply language filter
    if lang_filter:
        detected_langs = detected_langs & lang_filter
    if not detected_langs:
        return _error(commit_out, repo_full, sha, "no_matching_languages",
                      f"Detected languages don't match filter")

    # Filter out autobuild languages if no build system detected
    final_langs = set()
    for lang in detected_langs:
        if lang in LANGUAGES_AUTOBUILD and not detect_build_system(repo_dir):
            continue
        final_langs.add(lang)
    if not final_langs:
        return _error(commit_out, repo_full, sha, "no_buildable_languages",
                      "Only autobuild languages detected but no build system found")

    # Create CodeQL databases (one per language)
    commit_out.mkdir(parents=True, exist_ok=True)
    db_results: Dict[str, Any] = {}
    for lang in sorted(final_langs):
        db_path = commit_out / "db" / lang
        db_path.mkdir(parents=True, exist_ok=True)
        success, err_msg = create_codeql_db(
            codeql_bin, repo_dir, db_path, lang, db_timeout
        )
        db_results[lang] = {
            "success": success,
            "db_path": str(db_path),
        }
        if not success:
            db_results[lang]["error"] = err_msg

    # Write commit_info.json
    commit_info = {
        "repo": repo_full,
        "sha": sha,
        "parent_sha": parent_sha,
        "html_url": commit.get("html_url"),
        "commit_message": commit.get("commit_message"),
        "agents": commit.get("agents", []),
        "confidence": commit.get("confidence"),
        "detected_languages": sorted(final_langs),
        "changed_files": changed_files,
        "db_results": db_results,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }
    (commit_out / "commit_info.json").write_text(
        json.dumps(commit_info, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    successful_langs = [l for l, r in db_results.items() if r["success"]]
    failed_langs = [l for l, r in db_results.items() if not r["success"]]

    return {
        "status": "done",
        "repo": repo_full,
        "sha": sha,
        "successful_dbs": successful_langs,
        "failed_dbs": failed_langs,
    }


def _error(commit_out: Path, repo_full: str, sha: str,
           error_code: str, message: str) -> Dict[str, Any]:
    """Write an error.json and return error result."""
    commit_out.mkdir(parents=True, exist_ok=True)
    error_record = {
        "repo": repo_full,
        "sha": sha,
        "error": error_code,
        "message": message,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    (commit_out / "error.json").write_text(
        json.dumps(error_record, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return {"status": "error", **error_record}


def round_robin_by_repo(commits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Interleave commits from different repos for better parallelism."""
    by_repo: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in commits:
        by_repo[slug(c["repo"])].append(c)
    out: List[Dict[str, Any]] = []
    repo_keys = sorted(by_repo.keys())
    idx = 0
    while True:
        added = 0
        for rk in repo_keys:
            lst = by_repo[rk]
            if idx < len(lst):
                out.append(lst[idx])
                added += 1
        if added == 0:
            break
        idx += 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Create CodeQL databases from AI-assisted commits"
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
        help="Output directory for CodeQL databases",
    )
    ap.add_argument(
        "--workspace", type=Path, default=None,
        help="Clone workspace (default: <output-dir>/workspace)",
    )
    ap.add_argument(
        "--codeql", default="/home/yilegu/agent-blockchain-security/codeql/codeql/codeql",
        help="Path to CodeQL CLI binary",
    )
    ap.add_argument("--repo", type=str, default=None, help="Limit to one repo (owner/name)")
    ap.add_argument("--sha", type=str, default=None, help="Limit to one commit SHA")
    ap.add_argument("--jobs", "-j", type=int, default=1, help="Parallel workers (default 1)")
    ap.add_argument(
        "--languages", type=str, default=None,
        help="Comma-separated language filter (e.g. python,javascript,cpp)",
    )
    ap.add_argument(
        "--db-timeout", type=int, default=600,
        help="Timeout for CodeQL DB creation in seconds (default 600)",
    )
    ap.add_argument("--list-only", action="store_true", help="Only list commits and exit")
    args = ap.parse_args()

    crawl_dir = args.crawl_dir.resolve()
    output_dir = args.output_dir.resolve()
    workspace = (args.workspace or output_dir / "workspace").resolve()
    lang_filter: Optional[Set[str]] = None
    if args.languages:
        lang_filter = set(args.languages.split(","))

    # Gather all commits
    commits = iter_commits(crawl_dir, args.repo, args.sha)
    print(f"Found {len(commits)} commits total.", file=sys.stderr)

    if args.list_only:
        for c in commits:
            print(f"{c['repo']}\t{c['sha']}\t{','.join(c.get('agents', []))}")
        return

    # Filter already-done commits
    todo = [
        c for c in commits
        if not (output_dir / slug(c["repo"]) / c["sha"] / "commit_info.json").exists()
    ]
    skipped = len(commits) - len(todo)
    if skipped:
        print(f"[skip] {skipped} already done", file=sys.stderr)

    if not todo:
        print("Nothing to run.", file=sys.stderr)
        return

    jobs = max(1, args.jobs)
    if jobs > 1:
        todo = round_robin_by_repo(todo)

    output_dir.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)
    errors_jsonl = output_dir / "errors.jsonl"
    repo_locks: Dict[str, threading.Lock] = defaultdict(threading.Lock)

    total = len(todo)
    print(f"Running {total} commits with {jobs} workers.", file=sys.stderr)

    progress = {"completed": 0}
    progress_lock = threading.Lock()

    def run_one(commit: Dict[str, Any]) -> Dict[str, Any]:
        with repo_locks[slug(commit["repo"])]:
            result = process_one_commit(
                commit, workspace, output_dir,
                args.codeql, lang_filter, args.db_timeout,
            )
        # Log errors to global file
        if result.get("status") == "error":
            with progress_lock:
                with errors_jsonl.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(result, ensure_ascii=False) + "\n")
        # Progress
        with progress_lock:
            progress["completed"] += 1
            n = progress["completed"]
        status = result.get("status", "?")
        extra = ""
        if status == "done":
            extra = f" dbs={result.get('successful_dbs', [])}"
        elif status == "error":
            extra = f" err={result.get('error', '?')}"
        print(f"[{n}/{total}] {status} {commit['repo']} {commit['sha'][:10]}{extra}",
              file=sys.stderr)
        return result

    if jobs <= 1:
        for commit in todo:
            run_one(commit)
    else:
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            futures = {executor.submit(run_one, c): c for c in todo}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    c = futures[future]
                    print(f"[exception] {c['repo']} {c['sha'][:10]}: {exc}",
                          file=sys.stderr)

    print("Done.", file=sys.stderr)


if __name__ == "__main__":
    main()
