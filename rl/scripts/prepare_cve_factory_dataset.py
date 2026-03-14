#!/usr/bin/env python3
"""Prepare a verl-compatible dataset from CVE-Factory tasks.

Reads cve_factory_tasks.jsonl (produced by dataset/cve_factory_adapter.py) and
converts it into the same parquet format used by verl for RL training.

The task for the model: given a CVE task instruction, generate a bash solution
script (solution.sh) that fixes the vulnerability.

Usage:
    python scripts/prepare_cve_factory_dataset.py
    python scripts/prepare_cve_factory_dataset.py --index ../dataset/data/cve_factory_tasks.jsonl
    python scripts/prepare_cve_factory_dataset.py --split trainset-2  # simpler tasks only
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import pandas as pd


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_INDEX = PROJECT_ROOT.parent / "dataset" / "data" / "cve_factory_tasks.jsonl"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "cve_factory"

SYSTEM_PROMPT = (
    "You are a security engineer. You are given a description of a bug or "
    "vulnerability in a running application inside a Docker container. "
    "Write a bash script (solution.sh) that fixes the issue. "
    "The script will be executed inside the container with bash. "
    "It should modify the relevant source files and restart services if needed. "
    "Output ONLY the bash script content, starting with #!/bin/bash."
)


def build_prompt(instruction: str, tags: list[str]) -> list[dict]:
    """Build chat-format prompt for verl."""
    tag_str = ", ".join(tags) if tags else "general"
    user_msg = (
        f"{instruction}\n\n"
        f"Tags: {tag_str}\n\n"
        "Write a solution.sh bash script that fixes this issue."
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_msg},
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--index",
        type=Path,
        default=DEFAULT_INDEX,
        help="Path to cve_factory_tasks.jsonl",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Where to write train.parquet and val.parquet",
    )
    parser.add_argument(
        "--split",
        choices=["trainset", "trainset-2"],
        default=None,
        help="Only include tasks from this split",
    )
    parser.add_argument("--train-ratio", type=float, default=0.9)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if not args.index.exists():
        raise FileNotFoundError(
            f"Index not found: {args.index}\n"
            "Run: cd dataset && python cve_factory_adapter.py"
        )

    with open(args.index) as f:
        tasks = [json.loads(line) for line in f if line.strip()]

    if args.split:
        tasks = [t for t in tasks if t["split"] == args.split]

    print(f"Loaded {len(tasks)} CVE-Factory tasks")

    # Read reference solutions for ground_truth
    records = []
    skipped = 0
    for t in tasks:
        task_dir = Path(t["task_dir"])
        solution_path = task_dir / "solution.sh"

        if not task_dir.is_dir():
            skipped += 1
            continue

        ground_truth = ""
        if solution_path.exists():
            ground_truth = solution_path.read_text()

        records.append({
            "data_source": "cve_factory",
            "prompt": build_prompt(t["instruction"], t.get("tags", [])),
            "ground_truth": ground_truth,
            "reward_model": {"ground_truth": ground_truth},
            "task_id": t["task_id"],
            "extra_info": {
                "split": t.get("split", ""),
                "task_id": t["task_id"],
                "task_dir": t["task_dir"],
                "cve_id": t.get("cve_id", ""),
                "difficulty": t.get("difficulty", ""),
                "category": t.get("category", ""),
                "tags": t.get("tags", []),
            },
        })

    if skipped:
        print(f"Skipped {skipped} tasks (directory not found)")

    random.Random(args.seed).shuffle(records)
    split_idx = int(len(records) * args.train_ratio)
    train_records = records[:split_idx]
    val_records = records[split_idx:]

    args.output_dir.mkdir(parents=True, exist_ok=True)

    train_df = pd.DataFrame.from_records(train_records)
    val_df = pd.DataFrame.from_records(val_records)

    train_path = args.output_dir / "train.parquet"
    val_path = args.output_dir / "val.parquet"
    train_df.to_parquet(train_path, index=False)
    val_df.to_parquet(val_path, index=False)

    print(f"Wrote {len(train_df)} train rows to {train_path}")
    print(f"Wrote {len(val_df)} val rows to {val_path}")

    # Summary
    from collections import Counter
    cats = Counter(r["extra_info"]["category"] for r in records)
    diffs = Counter(r["extra_info"]["difficulty"] for r in records)
    print(f"Categories: {dict(cats)}")
    print(f"Difficulties: {dict(diffs)}")


if __name__ == "__main__":
    main()
