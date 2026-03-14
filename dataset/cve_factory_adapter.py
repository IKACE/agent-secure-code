#!/usr/bin/env python3
"""Index CVE-Factory tasks into a unified JSONL manifest.

Scans cve_factory/cve_tasks/{trainset,trainset-2}/ and writes a JSONL file
with one record per CVE task, containing all metadata needed for evaluation.

Usage:
    python cve_factory_adapter.py                     # default paths
    python cve_factory_adapter.py --cve-factory-dir data/cve_factory
    python cve_factory_adapter.py --split trainset-2  # only one split
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


SCRIPT_DIR = Path(__file__).parent
DEFAULT_CVE_FACTORY = SCRIPT_DIR / "data" / "cve_factory"
DEFAULT_OUTPUT = SCRIPT_DIR / "data" / "cve_factory_tasks.jsonl"

SPLITS = ["trainset", "trainset-2"]


def index_task(task_dir: Path, split: str) -> dict | None:
    """Read a single CVE-Factory task directory and return a record."""
    task_yaml = task_dir / "task.yaml"
    if not task_yaml.exists():
        return None

    with open(task_yaml) as f:
        meta = yaml.safe_load(f)

    # Verify required files
    required = ["docker-compose.yaml", "Dockerfile"]
    has_docker = any((task_dir / r).exists() for r in required)
    has_tests = (
        (task_dir / "tests" / "test_func.py").exists()
        and (task_dir / "tests" / "test_vuln.py").exists()
    )
    if not has_docker or not has_tests:
        return None

    cve_id = task_dir.name  # e.g. "cve-2024-0241"

    return {
        "task_id": f"cve_factory__{split}__{cve_id}",
        "source": "cve_factory",
        "cve_id": cve_id.upper(),
        "split": split,
        "task_dir": str(task_dir),
        "instruction": meta.get("instruction", ""),
        "difficulty": meta.get("difficulty", ""),
        "category": meta.get("category", ""),
        "tags": meta.get("tags", []),
        "has_solution": (task_dir / "solution.sh").exists(),
        "has_task_deps": (task_dir / "task-deps").is_dir(),
        "parser_name": meta.get("parser_name", "pytest"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cve-factory-dir",
        type=Path,
        default=DEFAULT_CVE_FACTORY,
        help="Path to cloned CVE-Factory repo.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output JSONL file.",
    )
    parser.add_argument(
        "--split",
        choices=SPLITS,
        default=None,
        help="Only index a specific split (default: all).",
    )
    args = parser.parse_args()

    cve_tasks_root = args.cve_factory_dir / "cve_tasks"
    if not cve_tasks_root.is_dir():
        raise FileNotFoundError(
            f"CVE-Factory tasks not found at {cve_tasks_root}. "
            "Clone the repo first: git clone https://github.com/livecvebench/CVE-Factory.git data/cve_factory"
        )

    splits = [args.split] if args.split else SPLITS
    records = []
    skipped = 0

    for split in splits:
        split_dir = cve_tasks_root / split
        if not split_dir.is_dir():
            print(f"Warning: split directory not found: {split_dir}")
            continue

        for task_dir in sorted(split_dir.iterdir()):
            if not task_dir.is_dir():
                continue
            rec = index_task(task_dir, split)
            if rec:
                records.append(rec)
            else:
                skipped += 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

    print(f"Indexed {len(records)} CVE-Factory tasks -> {args.output}")
    if skipped:
        print(f"Skipped {skipped} directories (missing required files)")

    # Summary by split
    from collections import Counter
    split_counts = Counter(r["split"] for r in records)
    for s, c in sorted(split_counts.items()):
        print(f"  {s}: {c}")


if __name__ == "__main__":
    main()
