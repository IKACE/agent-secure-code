#!/usr/bin/env python3
"""
Script 2: Run Vulnhalla on all CodeQL databases created by create_codeql_dbs.py.

Finds all CodeQL DBs under the output directory, maps CodeQL primaryLanguage
to Vulnhalla language codes, runs Vulnhalla headlessly via analyze_pipeline(),
and copies per-run results to the per-commit output directory.

Output structure per commit (appended to Script 1 output):
    <db_root>/<repo_slug>/<sha>/
        vulnhalla_results/          Copied from Vulnhalla output
            <issue_type>/
                N_raw.json
                N_final.json
        vulnhalla_summary.json      Per-commit summary

Usage:
    python run_vulnhalla_batch.py \
        --db-root ./ai_commit_dbs \
        --vulnhalla-dir ~/agent-blockchain-security/Vulnhalla \
        --jobs 1 \
        --skip-done
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# CodeQL primaryLanguage → Vulnhalla internal language code
CODEQL_TO_VULNHALLA: Dict[str, str] = {
    "cpp": "c",
    "c": "c",
    "python": "python",
    "javascript": "javascript",
}

# Vulnhalla-supported languages
VULNHALLA_SUPPORTED = frozenset({"c", "python", "javascript"})


def read_primary_language(db_path: Path) -> Optional[str]:
    """Read primaryLanguage from codeql-database.yml without YAML dependency."""
    yml = db_path / "codeql-database.yml"
    if not yml.exists():
        return None
    try:
        for line in yml.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("primaryLanguage:"):
                return stripped.split(":", 1)[1].strip().strip("'\"").lower()
    except OSError:
        pass
    return None


def find_all_dbs(db_root: Path) -> List[Dict[str, Any]]:
    """
    Find all CodeQL databases created by Script 1.
    Returns list of dicts with: repo_slug, sha, lang, db_path, commit_dir.
    """
    results = []
    if not db_root.exists():
        return results

    for repo_slug_dir in sorted(db_root.iterdir()):
        if not repo_slug_dir.is_dir() or repo_slug_dir.name in ("workspace", "errors.jsonl"):
            continue
        for sha_dir in sorted(repo_slug_dir.iterdir()):
            if not sha_dir.is_dir():
                continue
            db_dir = sha_dir / "db"
            if not db_dir.exists():
                continue
            # Each language has its own sub-DB
            for lang_dir in sorted(db_dir.iterdir()):
                if not lang_dir.is_dir():
                    continue
                yml = lang_dir / "codeql-database.yml"
                if not yml.exists():
                    continue
                primary_lang = read_primary_language(lang_dir)
                if not primary_lang:
                    continue
                results.append({
                    "repo_slug": repo_slug_dir.name,
                    "sha": sha_dir.name,
                    "codeql_lang": primary_lang,
                    "db_path": lang_dir,
                    "commit_dir": sha_dir,
                })
    return results


def map_to_vulnhalla_lang(codeql_lang: str) -> Optional[str]:
    """Map CodeQL language to Vulnhalla language code."""
    return CODEQL_TO_VULNHALLA.get(codeql_lang)


def run_vulnhalla_headless(
    db_path: Path,
    vulnhalla_lang: str,
    vulnhalla_dir: Path,
    timeout_seconds: int = 1800,
) -> Tuple[bool, str]:
    """
    Run Vulnhalla headlessly via subprocess using Poetry's virtualenv.
    This ensures all Vulnhalla dependencies (pySmartDL, etc.) are available.
    Returns (success, error_message).
    """
    # Clear any stale output from previous runs
    results_dir = vulnhalla_dir / "output" / "results" / vulnhalla_lang
    if results_dir.exists():
        shutil.rmtree(results_dir)

    # Call analyze_pipeline via poetry run so we get Vulnhalla's virtualenv
    script = (
        "from src.pipeline import analyze_pipeline; "
        f"analyze_pipeline(local_db_path={str(db_path)!r}, "
        f"lang={vulnhalla_lang!r}, open_ui=False)"
    )
    try:
        r = subprocess.run(
            ["poetry", "run", "python", "-c", script],
            cwd=str(vulnhalla_dir),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        if r.returncode != 0:
            # Extract meaningful error from stderr — look for ERROR lines first
            all_lines = r.stderr.strip().splitlines()
            error_lines = [l for l in all_lines if "ERROR" in l]
            if error_lines:
                err_msg = error_lines[0].strip()
            elif all_lines:
                err_msg = all_lines[-1].strip()
            else:
                err_msg = f"exit code {r.returncode}"
            return False, err_msg[:500]
        return True, ""
    except subprocess.TimeoutExpired:
        return False, f"Vulnhalla timed out after {timeout_seconds}s"
    except FileNotFoundError:
        return False, "poetry not found on PATH"


def copy_vulnhalla_results(
    vulnhalla_dir: Path,
    vulnhalla_lang: str,
    dest_dir: Path,
) -> Dict[str, Any]:
    """
    Copy Vulnhalla results from its output directory to the per-commit directory.
    Returns summary of results.
    """
    results_src = vulnhalla_dir / "output" / "results" / vulnhalla_lang
    results_dest = dest_dir / "vulnhalla_results"

    summary: Dict[str, Any] = {
        "total_issues": 0,
        "true_positives": 0,
        "false_positives": 0,
        "needs_more_data": 0,
        "issue_types": {},
    }

    if not results_src.exists():
        return summary

    # Copy results directory
    if results_dest.exists():
        shutil.rmtree(results_dest)
    shutil.copytree(results_src, results_dest)

    # Parse results and build summary
    for issue_type_dir in sorted(results_dest.iterdir()):
        if not issue_type_dir.is_dir():
            continue
        issue_type = issue_type_dir.name
        type_summary = {"true": 0, "false": 0, "more": 0, "findings": []}

        for final_file in sorted(issue_type_dir.glob("*_final.json")):
            try:
                raw_text = final_file.read_text(encoding="utf-8", errors="ignore")

                # _final.json uses Python repr format, not valid JSON.
                # Extract the assistant's response by finding text after the last
                # "'role': 'assistant'" marker — that's the LLM's actual decision.
                llm_content = ""
                assistant_marker = "'role': 'assistant'"
                last_idx = raw_text.rfind(assistant_marker)
                if last_idx >= 0:
                    llm_content = raw_text[last_idx:]

                if not llm_content:
                    # No assistant response found at all
                    continue

                # Find the LAST status code in the assistant's response
                import re
                codes = re.findall(r'\b(1337|1007|7331|3713)\b', llm_content)
                if not codes:
                    status = "needs_more_data"
                elif codes[-1] == "1337":
                    status = "true"
                elif codes[-1] == "1007":
                    status = "false"
                else:
                    status = "needs_more_data"

                if status == "true":
                    type_summary["true"] += 1
                    summary["true_positives"] += 1
                elif status == "false":
                    type_summary["false"] += 1
                    summary["false_positives"] += 1
                else:
                    type_summary["more"] += 1
                    summary["needs_more_data"] += 1

                summary["total_issues"] += 1

                # Try to extract file/line from raw file
                raw_file = final_file.parent / final_file.name.replace("_final.json", "_raw.json")
                file_path = ""
                line_num = 0
                if raw_file.exists():
                    try:
                        raw_data = json.loads(raw_file.read_text(encoding="utf-8"))
                        func = raw_data.get("current_function", {})
                        file_path = func.get("file", "").strip('"')
                        line_num = int(func.get("start_line", "0").strip('"'))
                    except (json.JSONDecodeError, ValueError, AttributeError):
                        pass

                type_summary["findings"].append({
                    "issue_id": final_file.stem.replace("_final", ""),
                    "status": status,
                    "file": file_path,
                    "line": line_num,
                    "llm_explanation": llm_content[:500] if llm_content else "",
                })

            except (json.JSONDecodeError, OSError):
                continue

        summary["issue_types"][issue_type] = type_summary

    return summary


def process_one_db(
    db_info: Dict[str, Any],
    vulnhalla_dir: Path,
    timeout: int = 1800,
) -> Dict[str, Any]:
    """Process a single CodeQL DB through Vulnhalla."""
    repo_slug = db_info["repo_slug"]
    sha = db_info["sha"]
    codeql_lang = db_info["codeql_lang"]
    db_path = db_info["db_path"]
    commit_dir = db_info["commit_dir"]

    vulnhalla_lang = map_to_vulnhalla_lang(codeql_lang)
    if not vulnhalla_lang:
        return {
            "status": "skipped",
            "repo_slug": repo_slug,
            "sha": sha,
            "reason": f"unsupported_language: {codeql_lang}",
        }

    # Run Vulnhalla
    start_time = time.time()
    success, err_msg = run_vulnhalla_headless(
        db_path, vulnhalla_lang, vulnhalla_dir, timeout
    )
    elapsed = time.time() - start_time

    if not success:
        error_record = {
            "status": "error",
            "repo_slug": repo_slug,
            "sha": sha,
            "language": vulnhalla_lang,
            "error": err_msg,
            "elapsed_seconds": round(elapsed, 1),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        error_path = commit_dir / f"vulnhalla_error_{vulnhalla_lang}.json"
        error_path.write_text(
            json.dumps(error_record, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return error_record

    # Copy results
    summary = copy_vulnhalla_results(vulnhalla_dir, vulnhalla_lang, commit_dir)
    summary["repo_slug"] = repo_slug
    summary["sha"] = sha
    summary["language"] = vulnhalla_lang
    summary["elapsed_seconds"] = round(elapsed, 1)
    summary["ts"] = datetime.now(timezone.utc).isoformat()

    # Write per-commit summary
    summary_path = commit_dir / "vulnhalla_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    return {"status": "done", **summary}


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Run Vulnhalla on CodeQL databases from create_codeql_dbs.py"
    )
    ap.add_argument(
        "--db-root", type=Path,
        default=Path(__file__).resolve().parent / "ai_commit_dbs",
        help="Root directory containing repo_slug/sha/db/ structures",
    )
    ap.add_argument(
        "--vulnhalla-dir", type=Path,
        default=Path.home() / "agent-blockchain-security" / "Vulnhalla",
        help="Path to Vulnhalla installation directory",
    )
    ap.add_argument("--repo", type=str, default=None,
                    help="Limit to one repo (owner__name slug)")
    ap.add_argument("--jobs", "-j", type=int, default=1,
                    help="Parallel workers (default 1; LLM calls are rate-limited)")
    ap.add_argument("--skip-done", action="store_true",
                    help="Skip DBs that already have vulnhalla_summary.json")
    ap.add_argument("--timeout", type=int, default=1800,
                    help="Timeout per Vulnhalla analysis in seconds (default 1800)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Only list DBs that would be processed")
    args = ap.parse_args()

    db_root = args.db_root.resolve()
    vulnhalla_dir = args.vulnhalla_dir.resolve()

    if not vulnhalla_dir.exists():
        print(f"[error] Vulnhalla directory not found: {vulnhalla_dir}", file=sys.stderr)
        sys.exit(1)

    # Find all DBs
    all_dbs = find_all_dbs(db_root)
    print(f"Found {len(all_dbs)} CodeQL databases.", file=sys.stderr)

    # Filter by repo
    if args.repo:
        all_dbs = [d for d in all_dbs if d["repo_slug"] == args.repo]

    # Filter to Vulnhalla-supported languages
    supported = [d for d in all_dbs if map_to_vulnhalla_lang(d["codeql_lang"]) is not None]
    unsupported = len(all_dbs) - len(supported)
    if unsupported:
        print(f"[skip] {unsupported} DBs with unsupported languages", file=sys.stderr)

    # Skip already-done
    if args.skip_done:
        todo = [d for d in supported
                if not (d["commit_dir"] / "vulnhalla_summary.json").exists()]
        skipped = len(supported) - len(todo)
        if skipped:
            print(f"[skip] {skipped} already have Vulnhalla results", file=sys.stderr)
    else:
        todo = supported

    if not todo:
        print("Nothing to run.", file=sys.stderr)
        return

    if args.dry_run:
        for d in todo:
            vl = map_to_vulnhalla_lang(d["codeql_lang"])
            print(f"{d['repo_slug']}\t{d['sha']}\t{d['codeql_lang']}→{vl}\t{d['db_path']}")
        return

    total = len(todo)
    print(f"Processing {total} databases.", file=sys.stderr)
    errors_jsonl = db_root / "vulnhalla_errors.jsonl"

    for idx, db_info in enumerate(todo, start=1):
        vl = map_to_vulnhalla_lang(db_info["codeql_lang"])
        print(
            f"[{idx}/{total}] {db_info['repo_slug']} {db_info['sha'][:10]} "
            f"lang={db_info['codeql_lang']}→{vl}",
            file=sys.stderr, flush=True,
        )
        result = process_one_db(db_info, vulnhalla_dir, args.timeout)
        status = result.get("status", "?")
        if status == "done":
            tp = result.get("true_positives", 0)
            fp = result.get("false_positives", 0)
            md = result.get("needs_more_data", 0)
            print(
                f"  -> {status}: {result.get('total_issues', 0)} issues "
                f"(TP={tp}, FP={fp}, more={md}) "
                f"in {result.get('elapsed_seconds', 0)}s",
                file=sys.stderr,
            )
        elif status == "error":
            print(f"  -> ERROR: {result.get('error', '?')}", file=sys.stderr)
            with errors_jsonl.open("a", encoding="utf-8") as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")
        else:
            print(f"  -> {status}: {result.get('reason', '')}", file=sys.stderr)

    print("Done.", file=sys.stderr)


if __name__ == "__main__":
    main()
