import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sarif_compare import ai_introduced_findings


def _parse_changed_lines(files: List[Dict[str, Any]]) -> Dict[str, Set[int]]:
    """
    Reconstruct the set of line numbers (in the after revision) that were
    changed by the commit, per file, from unified diff hunks in the GitHub
    commit JSON (files[].patch).
    """
    changed: Dict[str, Set[int]] = {}

    for f in files:
        filename = f.get("filename")
        patch = f.get("patch")
        if not filename or not patch:
            continue

        norm_name = filename.replace("\\", "/").strip("/")
        line_set = changed.setdefault(norm_name, set())

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
                # Context or other metadata; advance after line number
                new_line += 1

    return changed


def _iter_run_dirs(report_root: Path):
    """
    Yield (repo_slug_dir, sha_dir) for each CodeQL run directory that
    contains at least an after.sarif file.
    """
    if not report_root.exists():
        return

    for repo_dir in report_root.iterdir():
        if not repo_dir.is_dir():
            continue
        for sha_dir in repo_dir.iterdir():
            if not sha_dir.is_dir():
                continue
            after = sha_dir / "after.sarif"
            if after.exists():
                yield repo_dir, sha_dir


def rerun_attribution(
    report_root: Path,
    crawl_outdir: Path,
    only_repo: str | None = None,
) -> None:
    """
    Recompute codeql_report.json for all commits that already have after.sarif,
    using strict line-level attribution based on diff hunks.

    This does NOT rerun CodeQL; it only reuses existing SARIF and diff JSON.
    Findings are enriched with security_severity and severity_level from rule metadata.
    """
    updated = 0
    skipped_missing_diff = 0

    for repo_dir, sha_dir in _iter_run_dirs(report_root):
        repo_slug = repo_dir.name  # owner__repo with "__"
        repo_full = repo_slug.replace("__", "/", 1)
        if only_repo and repo_full != only_repo:
            continue

        sha = sha_dir.name
        before = sha_dir / "before.sarif"
        after = sha_dir / "after.sarif"

        diffs_dir = crawl_outdir / "repos" / repo_slug / "diffs"
        diff_json = diffs_dir / f"{sha}.json"
        if not diff_json.exists():
            skipped_missing_diff += 1
            continue

        try:
            diff = json.loads(diff_json.read_text(encoding="utf-8"))
        except Exception:
            skipped_missing_diff += 1
            continue

        files = diff.get("files") or []
        ai_edited = [f.get("filename") for f in files if f.get("filename")]
        changed_lines = _parse_changed_lines(files)

        introduced = ai_introduced_findings(
            after,
            ai_edited,
            changed_lines,
            repo_root_name="",
        )

        report_path = sha_dir / "codeql_report.json"
        base: Dict[str, Any] = {}
        if report_path.exists():
            try:
                base_loaded = json.loads(report_path.read_text(encoding="utf-8"))
                if isinstance(base_loaded, dict):
                    base = base_loaded
            except Exception:
                base = {}

        # Preserve existing metadata where possible, but always refresh AI fields.
        repo_meta = base.get("repo") or diff.get("repo") or repo_full
        parent_sha = base.get("parent_sha")
        html_url = base.get("html_url") or diff.get("html_url")

        new_report: Dict[str, Any] = {}
        for k, v in base.items():
            if k in {"ai_edited_files", "ai_introduced_findings", "num_ai_introduced"}:
                continue
            new_report[k] = v

        new_report.update(
            {
                "repo": repo_meta,
                "sha": sha,
                "parent_sha": parent_sha,
                "html_url": html_url,
                "ai_edited_files": ai_edited,
                "ai_introduced_findings": introduced,
                "num_ai_introduced": len(introduced),
            }
        )

        report_path.write_text(json.dumps(new_report, indent=2, ensure_ascii=False), encoding="utf-8")
        updated += 1
        print(f"[updated] {repo_full} {sha} ai_introduced={len(introduced)}")

    print(f"Done. Updated {updated} commits. Skipped {skipped_missing_diff} without matching diff JSON.", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Re-run line-level AI attribution for existing CodeQL runs using "
            "after.sarif and GitHub diff hunks (no CodeQL re-analysis)."
        )
    )
    parser.add_argument(
        "--report-root",
        default=os.environ.get("PATCH_ANALYSIS_REPORT_DIR") or str(
            Path(__file__).resolve().parent / "output"
        ),
        help=(
            "Root directory containing {owner__repo}/{sha}/before.sarif and after.sarif "
            "(default: PATCH_ANALYSIS_REPORT_DIR or patch_analysis/output)."
        ),
    )
    parser.add_argument(
        "--crawl-outdir",
        default="output",
        help="Crawl output directory containing repos/{owner__repo}/diffs/*.json (default: output).",
    )
    parser.add_argument(
        "--repo",
        help="Optional owner/name to restrict to a single repository.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report_root = Path(args.report_root).resolve()
    crawl_outdir = Path(args.crawl_outdir).resolve()
    rerun_attribution(report_root, crawl_outdir, only_repo=args.repo)


if __name__ == "__main__":
    main()

