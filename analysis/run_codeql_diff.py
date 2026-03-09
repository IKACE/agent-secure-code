#!/usr/bin/env python3
"""
Run CodeQL on repo at parent commit (before) and at AI commit (after), then compare
SARIF results to attribute new vulnerabilities in AI-edited files to the AI-assisted commit.

Reads crawl output: <crawl_outdir>/repos/<owner__repo>/diffs/<sha>.json
Each diff JSON has: repo, sha, files[].filename.

Workflow per AI commit:
  1. Clone repo (or reuse) into workspace/<owner__repo>.
  2. git fetch (if needed), checkout parent → CodeQL database create + analyze → before.sarif
  3. Checkout <sha> → CodeQL database create + analyze → after.sarif
  4. Compare: findings in after that are in files[] and not in before → AI-introduced.
  5. Write report to report_dir/<owner__repo>/<sha>/codeql_report.json

Requires: CodeQL CLI on PATH (codeql), git.
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

import re

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sarif_compare import ai_introduced_findings


def slug(repo_full: str) -> str:
    return repo_full.replace("/", "__")


def ensure_commit(repo_dir: Path, sha: str) -> bool:
    """Return True if the given commit is in the repo (for shallow clones, try unshallow)."""
    r = subprocess.run(
        ["git", "rev-parse", "--verify", f"{sha}^{{commit}}"],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if r.returncode == 0:
        return True
    try:
        subprocess.run(
            ["git", "fetch", "origin", "--unshallow"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return False
    r = subprocess.run(
        ["git", "rev-parse", "--verify", f"{sha}^{{commit}}"],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.returncode == 0


def get_parent_sha(repo_dir: Path, sha: str) -> Optional[str]:
    try:
        r = subprocess.run(
            ["git", "rev-parse", f"{sha}^"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode == 0 and r.stdout:
            return r.stdout.strip()
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def languages_from_files(files: List[Dict[str, Any]]) -> Set[str]:
    lang = set()
    for f in files:
        name = (f.get("filename") or "").lower()
        if name.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
            lang.add("javascript")
        elif name.endswith(".py"):
            lang.add("python")
        elif name.endswith(".go"):
            lang.add("go")
        elif name.endswith((".java", ".kt")):
            lang.add("java")
        elif name.endswith((".cpp", ".cc", ".cxx", ".c", ".h", ".hpp")):
            lang.add("cpp")
        elif name.endswith(".rb"):
            lang.add("ruby")
        elif name.endswith(".cs"):
            lang.add("csharp")
    return lang or {"javascript", "python"}


# CodeQL build-mode per language
LANGUAGES_BUILD_NONE = frozenset({"javascript", "python", "ruby", "csharp", "java"})
LANGUAGES_AUTOBUILD = frozenset({"cpp", "go", "swift"})
CLUSTER_LANGUAGE_NAMES = frozenset(
    {"javascript", "python", "ruby", "csharp", "java", "cpp", "go", "swift", "rust", "kotlin"}
)


def _build_mode_for_languages(languages: Set[str]) -> Optional[str]:
    if not languages:
        return None
    if languages & LANGUAGES_AUTOBUILD:
        return "autobuild"
    if languages <= LANGUAGES_BUILD_NONE:
        return "none"
    return "none"


def run_codeql_create(
    codeql_bin: str,
    repo_dir: Path,
    db_path: Path,
    languages: Set[str],
) -> bool:
    lang_list = sorted(languages)
    use_cluster = len(lang_list) > 1
    cmd = [
        codeql_bin,
        "database",
        "create",
        "--source-root",
        str(repo_dir),
        "--overwrite",
    ]
    if use_cluster:
        cmd.append("--db-cluster")
    for lang in lang_list:
        cmd.extend(["--language", lang])
    build_mode = _build_mode_for_languages(languages)
    if build_mode is not None:
        cmd.append(f"--build-mode={build_mode}")
    cmd.append(str(db_path))
    try:
        r = subprocess.run(
            cmd,
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if r.returncode != 0:
            print(f"[codeql create] exit {r.returncode}", file=sys.stderr)
            if r.stderr:
                print(r.stderr, file=sys.stderr)
            return False
        return True
    except subprocess.TimeoutExpired:
        print("[codeql create] timed out", file=sys.stderr)
        return False
    except FileNotFoundError:
        print("[codeql create] codeql not found", file=sys.stderr)
        return False


def _codeql_dist_root(codeql_bin: str) -> Optional[Path]:
    path = Path(codeql_bin).resolve() if os.path.isabs(codeql_bin) else Path(shutil.which(codeql_bin) or "")
    if not path.exists():
        return None
    return path.parent


def _is_cluster_db(db_path: Path) -> Optional[List[str]]:
    if not db_path.is_dir():
        return None
    subdirs = [d.name for d in db_path.iterdir() if d.is_dir() and d.name in CLUSTER_LANGUAGE_NAMES]
    return sorted(subdirs) if subdirs else None


def _merge_sarif_files(sarif_paths: List[Path], output_path: Path) -> bool:
    runs: List[Dict[str, Any]] = []
    version = "2.1.0"
    for p in sarif_paths:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            version = data.get("version", version)
            for r in data.get("runs") or []:
                runs.append(r)
        except (json.JSONDecodeError, OSError):
            continue
    if not runs:
        return False
    merged = {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif/master/sarif-schema-2.1.0.json", "version": version, "runs": runs}
    output_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
    return True


def resolve_codeql_suites_dir(codeql_bin: str) -> Optional[Path]:
    dist_root = _codeql_dist_root(codeql_bin)
    if dist_root and (dist_root / "codeql-suites").exists():
        return dist_root / "codeql-suites"
    if os.environ.get("CODEQL_HOME"):
        p = Path(os.environ["CODEQL_HOME"]) / "codeql-suites"
        if p.exists():
            return p
    return None


def resolve_suite_paths_from_qlpacks(codeql_bin: str, languages: Set[str]) -> List[str]:
    dist_root = _codeql_dist_root(codeql_bin)
    if not dist_root:
        return []
    qlpacks = dist_root / "qlpacks"
    if not qlpacks.exists():
        return []
    out = []
    for lang in sorted(languages):
        name = f"{lang}-security-extended.qls"
        for qls in qlpacks.rglob(f"**/codeql-suites/{name}"):
            out.append(str(qls))
            break
    return out


def run_codeql_analyze(
    codeql_bin: str,
    db_path: Path,
    output_sarif: Path,
    languages: Set[str],
    codeql_suites_dir: Optional[Path] = None,
    timeout_seconds: int = 1800,
) -> bool:
    cluster_langs = _is_cluster_db(db_path)
    if cluster_langs:
        temp_dir = output_sarif.parent / ".sarif_merge"
        temp_dir.mkdir(parents=True, exist_ok=True)
        try:
            merged_paths: List[Path] = []
            for lang in cluster_langs:
                lang_db = db_path / lang
                if not lang_db.is_dir():
                    continue
                suite_paths = resolve_suite_paths_from_qlpacks(codeql_bin, {lang})
                if not suite_paths:
                    suite_paths = [f"codeql-suites/{lang}-security-extended.qls"]
                out_part = temp_dir / f"{lang}.sarif"
                cmd = [
                    codeql_bin,
                    "database",
                    "analyze",
                    str(lang_db),
                    "--format",
                    "sarif-latest",
                    "--output",
                    str(out_part),
                    *suite_paths,
                ]
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    print(f"[codeql analyze] {lang}: timed out", file=sys.stderr)
                    return False
                if r.returncode != 0 and r.stderr:
                    print(f"[codeql analyze] {lang}: exit {r.returncode}", file=sys.stderr)
                    print(r.stderr, file=sys.stderr)
                elif out_part.exists():
                    merged_paths.append(out_part)
            if not merged_paths:
                return False
            return _merge_sarif_files(merged_paths, output_sarif)
        finally:
            if temp_dir.exists():
                for f in temp_dir.iterdir():
                    try:
                        f.unlink()
                    except OSError:
                        pass
                try:
                    temp_dir.rmdir()
                except OSError:
                    pass

    suite_paths = []
    if codeql_suites_dir:
        suite_paths = [str(p) for p in (codeql_suites_dir / f"{lang}-security-extended.qls" for lang in sorted(languages)) if p.exists()]
    if not suite_paths:
        suites_dir = resolve_codeql_suites_dir(codeql_bin)
        if suites_dir:
            suite_paths = [str(p) for p in (suites_dir / f"{lang}-security-extended.qls" for lang in sorted(languages)) if p.exists()]
    if not suite_paths:
        suite_paths = resolve_suite_paths_from_qlpacks(codeql_bin, languages)
    if not suite_paths:
        suite_paths = [f"codeql-suites/{lang}-security-extended.qls" for lang in sorted(languages)]
    cmd = [
        codeql_bin,
        "database",
        "analyze",
        str(db_path),
        "--format",
        "sarif-latest",
        "--output",
        str(output_sarif),
        *suite_paths,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        if r.returncode != 0:
            print(f"[codeql analyze] exit {r.returncode}", file=sys.stderr)
            if r.stderr:
                print(r.stderr, file=sys.stderr)
            return False
        return output_sarif.exists()
    except subprocess.TimeoutExpired:
        print("[codeql analyze] timed out", file=sys.stderr)
        return False
    except FileNotFoundError:
        print("[codeql analyze] codeql not found", file=sys.stderr)
        return False


def git_checkout(repo_dir: Path, ref: str) -> bool:
    try:
        subprocess.run(
            ["git", "checkout", "--force", ref],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=30,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def git_clone(repo_url: str, dest: Path, shallow: bool = False) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return True
    try:
        cmd = ["git", "clone"]
        if shallow:
            cmd.extend(["--depth", "500"])
        cmd.extend([repo_url, str(dest)])
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return dest.exists()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def process_one_commit(
    crawl_outdir: Path,
    workspace: Path,
    report_outdir: Path,
    repo_full: str,
    sha: str,
    codeql_bin: str,
    repo_url: Optional[str] = None,
    codeql_suites_dir: Optional[Path] = None,
    analyze_timeout: int = 1800,
) -> Dict[str, Any]:
    if not shutil.which(codeql_bin):
        return {"error": "codeql_not_found", "repo": repo_full, "sha": sha}
    repo_slug = slug(repo_full)
    diff_path = crawl_outdir / "repos" / repo_slug / "diffs" / f"{sha}.json"
    if not diff_path.exists():
        return {"error": "diff_not_found", "repo": repo_full, "sha": sha}

    diff = json.loads(diff_path.read_text(encoding="utf-8"))
    files = diff.get("files") or []
    ai_edited = [f.get("filename") for f in files if f.get("filename")]

    # Compute the exact after-commit line numbers that were changed by this AI-assisted commit
    # for each file, based on the unified diff hunks in `patch`.
    changed_lines: Dict[str, Set[int]] = {}

    for f in files:
        filename = f.get("filename")
        patch = f.get("patch")
        if not filename or not patch:
            continue
        norm_name = filename.replace("\\", "/").strip("/")
        line_set = changed_lines.setdefault(norm_name, set())

        new_line = None
        for raw in patch.splitlines():
            if raw.startswith("@@"):
                # Example hunk header: @@ -a,b +c,d @@ or @@ -a +c,d @@
                m = re.search(r"\+(\d+)(?:,(\d+))?", raw)
                if not m:
                    new_line = None
                    continue
                new_line = int(m.group(1))
                continue

            if new_line is None:
                continue

            if raw.startswith("+") and not raw.startswith("+++"):
                # Added/modified line in the after revision
                line_set.add(new_line)
                new_line += 1
            elif raw.startswith("-") and not raw.startswith("---"):
                # Deletion: advances only the old side, so new_line stays the same
                continue
            else:
                # Context line (' ') or other metadata: advances the after line number
                new_line += 1

    repo_dir = workspace / repo_slug
    if not repo_dir.exists():
        url = repo_url or f"https://github.com/{repo_full}.git"
        if not git_clone(url, repo_dir):
            return {"error": "clone_failed", "repo": repo_full, "sha": sha}

    if not ensure_commit(repo_dir, sha):
        return {"error": "fetch_commit_failed", "repo": repo_full, "sha": sha}
    parent_sha = get_parent_sha(repo_dir, sha)
    if not parent_sha:
        return {"error": "parent_sha_failed", "repo": repo_full, "sha": sha}

    languages = languages_from_files(files)
    run_dir = report_outdir / repo_slug / sha
    run_dir.mkdir(parents=True, exist_ok=True)
    db_before = run_dir / "db_before"
    db_after = run_dir / "db_after"
    before_sarif = run_dir / "before.sarif"
    after_sarif = run_dir / "after.sarif"

    if not git_checkout(repo_dir, parent_sha):
        return {"error": "checkout_parent_failed", "repo": repo_full, "sha": sha}
    if not run_codeql_create(codeql_bin, repo_dir, db_before, languages):
        return {"error": "codeql_create_before_failed", "repo": repo_full, "sha": sha}
    if not run_codeql_analyze(codeql_bin, db_before, before_sarif, languages, codeql_suites_dir, analyze_timeout):
        return {"error": "codeql_analyze_before_failed", "repo": repo_full, "sha": sha}

    if not git_checkout(repo_dir, sha):
        return {"error": "checkout_after_failed", "repo": repo_full, "sha": sha}
    if not run_codeql_create(codeql_bin, repo_dir, db_after, languages):
        return {"error": "codeql_create_after_failed", "repo": repo_full, "sha": sha}
    if not run_codeql_analyze(codeql_bin, db_after, after_sarif, languages, codeql_suites_dir, analyze_timeout):
        return {"error": "codeql_analyze_after_failed", "repo": repo_full, "sha": sha}

    introduced = ai_introduced_findings(after_sarif, ai_edited, changed_lines, repo_root_name="")

    report = {
        "repo": repo_full,
        "sha": sha,
        "parent_sha": parent_sha,
        "html_url": diff.get("html_url"),
        "ai_edited_files": ai_edited,
        "ai_introduced_findings": introduced,
        "num_ai_introduced": len(introduced),
    }
    (run_dir / "codeql_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def round_robin_by_repo(pairs: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    by_repo: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    for repo_full, sha in pairs:
        by_repo[slug(repo_full)].append((repo_full, sha))
    out = []
    repoS = sorted(by_repo.keys())
    idx = 0
    while True:
        added = 0
        for rs in repoS:
            lst = by_repo[rs]
            if idx < len(lst):
                out.append(lst[idx])
                added += 1
        if added == 0:
            break
        idx += 1
    return out


def iter_repos_and_shas(crawl_outdir: Path) -> List[Tuple[str, str]]:
    repos_dir = crawl_outdir / "repos"
    if not repos_dir.exists():
        return []
    out = []
    for repo_slug in sorted(repos_dir.iterdir()):
        if not repo_slug.is_dir():
            continue
        diffs_dir = repo_slug / "diffs"
        if not diffs_dir.exists():
            continue
        for p in diffs_dir.glob("*.json"):
            if p.name.endswith(".state.json"):
                continue
            sha = p.stem
            repo_full = repo_slug.name.replace("__", "/", 1)
            out.append((repo_full, sha))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="CodeQL before/after diff for AI commit vulnerability attribution")
    ap.add_argument("--crawl-outdir", type=Path, default=Path("output"), help="Crawl output dir (repos/.../diffs/)")
    ap.add_argument("--workspace", type=Path, default=None, help="Clone workspace (default: PATCH_ANALYSIS_WORKSPACE env or patch_analysis/workspace)")
    ap.add_argument("--report-dir", type=Path, default=None, help="Report output (default: PATCH_ANALYSIS_REPORT_DIR env or patch_analysis/output)")
    ap.add_argument("--codeql", default="codeql", help="CodeQL CLI binary")
    ap.add_argument("--codeql-suites-dir", type=Path, default=None, help="Path to codeql-suites")
    ap.add_argument("--repo", type=str, default=None, help="Limit to one repo (owner/name)")
    ap.add_argument("--sha", type=str, default=None, help="Limit to one commit SHA")
    ap.add_argument("--list-only", action="store_true", help="Only list repos/shas and exit")
    ap.add_argument("--no-skip-done", action="store_true", help="Re-run even if codeql_report.json already exists")
    ap.add_argument("--analyze-timeout", type=int, default=1800, help="CodeQL analyze timeout in seconds (default 1800)")
    ap.add_argument("--jobs", "-j", type=int, default=1, help="Run up to N commits in parallel (default 1)")
    args = ap.parse_args()

    crawl = args.crawl_outdir.resolve()
    default_workspace = (os.environ.get("PATCH_ANALYSIS_WORKSPACE") or "").strip()
    workspace = (args.workspace or (Path(default_workspace) if default_workspace else None) or Path(__file__).resolve().parent / "workspace").resolve()
    default_report_dir = (os.environ.get("PATCH_ANALYSIS_REPORT_DIR") or "").strip()
    report_dir = (args.report_dir or (Path(default_report_dir) if default_report_dir else None) or Path(__file__).resolve().parent / "output").resolve()

    pairs = iter_repos_and_shas(crawl)
    if args.repo:
        pairs = [(r, s) for r, s in pairs if r == args.repo]
    if args.sha:
        pairs = [(r, s) for r, s in pairs if s == args.sha]

    if args.list_only:
        for r, s in pairs:
            print(f"{r}\t{s}")
        return

    report_dir.mkdir(parents=True, exist_ok=True)
    errors_jsonl = report_dir / "errors.jsonl"
    jobs = max(1, args.jobs)
    repo_locks: Dict[str, threading.Lock] = defaultdict(threading.Lock)
    start_log_lock = threading.Lock() if jobs > 1 else None

    def run_one(repo_full: str, sha: str) -> Tuple[str, str, Dict[str, Any]]:
        with repo_locks[slug(repo_full)]:
            if start_log_lock:
                with start_log_lock:
                    print(f"[start] {repo_full} {sha}", file=sys.stderr)
                    sys.stderr.flush()
            report = process_one_commit(
                crawl, workspace, report_dir, repo_full, sha, args.codeql,
                codeql_suites_dir=args.codeql_suites_dir,
                analyze_timeout=args.analyze_timeout,
            )
        return (repo_full, sha, report)

    todo = [
        (repo_full, sha)
        for repo_full, sha in pairs
        if args.no_skip_done or not (report_dir / slug(repo_full) / sha / "codeql_report.json").exists()
    ]
    if jobs > 1 and todo:
        todo = round_robin_by_repo(todo)
        print("Ordered by repo (round-robin) for better parallelism.", file=sys.stderr)
    skipped = len(pairs) - len(todo)
    total = len(todo)
    if skipped:
        print(f"[skip] {skipped} already done", file=sys.stderr)
    if total == 0:
        print("Nothing to run.", file=sys.stderr)
        return
    print(f"Running {total} commits with -j {jobs} workers.", file=sys.stderr)

    progress = {"completed": 0}
    progress_lock = threading.Lock() if jobs > 1 else None

    def done_msg(repo_full: str, sha: str, report: Dict[str, Any]) -> str:
        if "error" in report:
            return f"[skip] {repo_full} {sha}: {report['error']}"
        return f"[done] {repo_full} {sha} ai_introduced={report.get('num_ai_introduced', 0)}"

    def emit_progress(msg: str) -> None:
        if progress_lock:
            with progress_lock:
                progress["completed"] += 1
                n, t = progress["completed"], total
            print(f"{msg} ({n}/{t})", file=sys.stderr)
            sys.stderr.flush()
        else:
            progress["completed"] += 1
            print(f"{msg} ({progress['completed']}/{total})", file=sys.stderr)

    if jobs <= 1:
        for repo_full, sha in todo:
            _, _, report = run_one(repo_full, sha)
            repo_slug = slug(repo_full)
            if "error" in report:
                if report.get("error") == "codeql_not_found":
                    print("  Add codeql to PATH or run with --codeql /path/to/codeql", file=sys.stderr)
                run_dir = report_dir / repo_slug / sha
                run_dir.mkdir(parents=True, exist_ok=True)
                error_record = {**report, "ts": datetime.now(timezone.utc).isoformat()}
                (run_dir / "error.json").write_text(json.dumps(error_record, indent=2, ensure_ascii=False), encoding="utf-8")
                with errors_jsonl.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(error_record, ensure_ascii=False) + "\n")
            emit_progress(done_msg(repo_full, sha, report))
    else:
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            future_to_pair = {executor.submit(run_one, repo_full, sha): (repo_full, sha) for repo_full, sha in todo}
            for future in as_completed(future_to_pair):
                repo_full, sha, report = future.result()
                repo_slug = slug(repo_full)
                if "error" in report:
                    if report.get("error") == "codeql_not_found":
                        print("  Add codeql to PATH or run with --codeql /path/to/codeql", file=sys.stderr)
                    run_dir = report_dir / repo_slug / sha
                    run_dir.mkdir(parents=True, exist_ok=True)
                    error_record = {**report, "ts": datetime.now(timezone.utc).isoformat()}
                    (run_dir / "error.json").write_text(json.dumps(error_record, indent=2, ensure_ascii=False), encoding="utf-8")
                    with errors_jsonl.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(error_record, ensure_ascii=False) + "\n")
                emit_progress(done_msg(repo_full, sha, report))


if __name__ == "__main__":
    main()
