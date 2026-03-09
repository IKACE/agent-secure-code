import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Set


def find_db_after_dirs(root: Path) -> List[Path]:
    """
    Recursively find all directories named 'db_after' under the given root.
    """
    db_dirs: List[Path] = []
    if not root.exists():
        return db_dirs

    for dirpath, dirnames, _ in os.walk(root):
        if "db_after" in dirnames:
            db_dirs.append(Path(dirpath) / "db_after")

    db_dirs.sort()
    return db_dirs


def _read_primary_language(db_yml: Path) -> Optional[str]:
    """
    Parse `primaryLanguage` from a codeql-database.yml file.
    Uses lightweight line parsing to avoid extra dependencies.
    """
    try:
        with db_yml.open("r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if line.startswith("primaryLanguage:"):
                    return line.split(":", 1)[1].strip().strip("'\"").lower()
    except OSError:
        return None
    return None


def find_c_cpp_db_paths(db_after_dir: Path) -> List[Path]:
    """
    Find CodeQL DB directories under `db_after_dir` whose primaryLanguage is C/C++.
    """
    accepted: Set[str] = {"c", "cpp", "c++"}
    db_paths: List[Path] = []

    for yml in db_after_dir.rglob("codeql-database.yml"):
        lang = _read_primary_language(yml)
        if lang in accepted:
            db_paths.append(yml.parent)

    db_paths.sort()
    return db_paths


def run_vulnhalla(db_dir: Path, vulnhalla_dir: Path, dry_run: bool = False) -> int:
    """
    Run 'poetry run vulnhalla --local <db_dir>' from the Vulnhalla project directory.

    Returns the process return code.
    """
    cmd = ["poetry", "run", "vulnhalla", "--local", str(db_dir)]

    if dry_run:
        print(f"[dry-run] (cwd={vulnhalla_dir}) Would run:", " ".join(cmd))
        return 0

    proc = subprocess.run(
        cmd,
        cwd=str(vulnhalla_dir),
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    return proc.returncode


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run vulnhalla over all CodeQL 'db_after' databases found under a root directory.\n"
            "Example command per database:\n"
            "  poetry run vulnhalla --local /mnt/storage/.../db_after"
        )
    )
    parser.add_argument(
        "--db-root",
        default=os.environ.get("PATCH_ANALYSIS_REPORT_DIR")
        or str(Path(__file__).resolve().parent / "output"),
        help=(
            "Root directory containing {owner__repo}/{sha}/db_after directories. "
            "Defaults to PATCH_ANALYSIS_REPORT_DIR or ./output next to this script."
        ),
    )
    parser.add_argument(
        "--vulnhalla-dir",
        default=os.environ.get("VULNHALLA_DIR")
        or str(Path.home() / "agent-blockchain-security" / "Vulnhalla"),
        help=(
            "Directory where Vulnhalla is installed (where 'poetry run vulnhalla' "
            "should be executed). Defaults to $VULNHALLA_DIR or "
            "~/agent-blockchain-security/Vulnhalla."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only print the commands that would be run, without executing vulnhalla.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(args.db_root).resolve()
    vulnhalla_dir = Path(args.vulnhalla_dir).expanduser().resolve()

    print(f"Scanning for 'db_after' directories under: {root}")
    db_dirs = find_db_after_dirs(root)

    if not db_dirs:
        print("No 'db_after' directories found.", file=sys.stderr)
        sys.exit(1)

    total = len(db_dirs)
    print(f"Found {total} 'db_after' directories.")
    print("Filtering to CodeQL databases with primaryLanguage in {c, cpp, c++} ...")

    failures: List[Path] = []
    skipped: List[Path] = []
    c_cpp_dbs: List[Path] = []

    for db_after_dir in db_dirs:
        matched = find_c_cpp_db_paths(db_after_dir)
        if matched:
            c_cpp_dbs.extend(matched)
        else:
            skipped.append(db_after_dir)

    if not c_cpp_dbs:
        print("No C/C++ databases found after filtering.", file=sys.stderr)
        sys.exit(1)

    print(f"Will run Vulnhalla on {len(c_cpp_dbs)} C/C++ database(s).")
    if skipped:
        print(f"Skipping {len(skipped)} non-C/C++ 'db_after' directories.")

    for idx, db_dir in enumerate(c_cpp_dbs, start=1):
        print(f"[{idx}/{len(c_cpp_dbs)}] Running vulnhalla on {db_dir} ...", flush=True)
        rc = run_vulnhalla(db_dir, vulnhalla_dir=vulnhalla_dir, dry_run=args.dry_run)
        if rc == 0:
            print(f"[{idx}/{len(c_cpp_dbs)}] Success for {db_dir}")
        else:
            print(
                f"[{idx}/{len(c_cpp_dbs)}] FAILED with exit code {rc} for {db_dir}",
                file=sys.stderr,
            )
            failures.append(db_dir)

    if failures:
        print(
            f"Completed with {len(failures)} failures out of {len(c_cpp_dbs)} runs.",
            file=sys.stderr,
        )
        for failed in failures:
            print(f"  - {failed}", file=sys.stderr)
        sys.exit(1)

    print(f"Done. Successfully processed all {len(c_cpp_dbs)} filtered C/C++ databases.")


if __name__ == "__main__":
    main()

