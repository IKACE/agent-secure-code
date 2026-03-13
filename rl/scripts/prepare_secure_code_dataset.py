#!/usr/bin/env python3
"""Prepare a verl-compatible dataset from secure-code task directories."""

from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path

import pandas as pd


TASKS_DIR_DEFAULT = Path(__file__).resolve().parent.parent.parent / "dataset" / "data" / "tasks"
OUTPUT_DIR_DEFAULT = Path(__file__).resolve().parent.parent / "data" / "secure_code"


def extract_setup_and_signature(prompt_md: str) -> tuple[str, str]:
    """Extract setup code and function signature from prompt.md."""
    blocks = re.findall(r"```(?:js|py|javascript|python|ts|typescript)\n(.*?)```", prompt_md, re.DOTALL)
    setup_code = blocks[0].rstrip("\n") if len(blocks) >= 1 else ""
    func_signature = blocks[1].rstrip("\n") if len(blocks) >= 2 else ""
    return setup_code, func_signature


def detect_language(task_dir: Path) -> str:
    """Detect task language from files present."""
    if (task_dir / "standalone.js").exists():
        return "javascript"
    if (task_dir / "standalone.py").exists():
        return "python"
    task_json = task_dir / "task.json"
    if task_json.exists():
        return json.loads(task_json.read_text()).get("language", "unknown")
    return "unknown"


def build_prompt(prompt_md: str) -> list[dict]:
    """Build chat-format prompt for verl (required by tokenizer.apply_chat_template)."""
    return [{"role": "user", "content": prompt_md.strip()}]


def load_tasks(tasks_dir: Path) -> list[dict]:
    """Load all tasks that have both correctness and security tests."""
    tasks = []
    for task_dir in sorted(tasks_dir.iterdir()):
        if not task_dir.is_dir():
            continue
        prompt_path = task_dir / "prompt.md"
        if not prompt_path.exists():
            continue
        tests_dir = task_dir / "tests"
        has_correctness = (tests_dir / "test_correctness.js").exists() or (tests_dir / "test_correctness.py").exists()
        has_security = (tests_dir / "test_security.js").exists() or (tests_dir / "test_security.py").exists()
        if not (has_correctness and has_security):
            continue

        prompt_md = prompt_path.read_text()
        setup_code, func_signature = extract_setup_and_signature(prompt_md)
        lang = detect_language(task_dir)

        # Read ground truth (secure version)
        gt_name = "standalone_secure.js" if lang == "javascript" else "standalone_secure.py"
        gt_path = task_dir / gt_name
        ground_truth = gt_path.read_text() if gt_path.exists() else ""

        task_id = task_dir.name

        tasks.append({
            "task_id": task_id,
            "prompt_md": prompt_md,
            "setup_code": setup_code,
            "func_signature": func_signature,
            "ground_truth": ground_truth,
            "language": lang,
            "task_dir": str(task_dir),
        })

    return tasks


def convert_rows(tasks: list[dict], split: str) -> pd.DataFrame:
    records = []
    for t in tasks:
        records.append({
            "data_source": "secure_code",
            "prompt": build_prompt(t["prompt_md"]),
            "ground_truth": t["ground_truth"],
            "reward_model": {"ground_truth": t["ground_truth"]},
            "task_id": t["task_id"],
            "extra_info": {
                "split": split,
                "task_id": t["task_id"],
                "task_dir": t["task_dir"],
                "language": t["language"],
                "setup_code": t["setup_code"],
                "func_signature": t["func_signature"],
            },
        })
    return pd.DataFrame.from_records(records)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare secure-code dataset for verl RL training")
    parser.add_argument("--tasks-dir", type=Path, default=TASKS_DIR_DEFAULT)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR_DEFAULT)
    parser.add_argument("--train-ratio", type=float, default=0.85)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    tasks = load_tasks(args.tasks_dir)
    print(f"Loaded {len(tasks)} tasks from {args.tasks_dir}")

    lang_counts = {}
    for t in tasks:
        lang_counts[t["language"]] = lang_counts.get(t["language"], 0) + 1
    print(f"Languages: {lang_counts}")

    random.Random(args.seed).shuffle(tasks)
    split_idx = int(len(tasks) * args.train_ratio)
    train_tasks = tasks[:split_idx]
    val_tasks = tasks[split_idx:]

    args.output_dir.mkdir(parents=True, exist_ok=True)

    train_df = convert_rows(train_tasks, "train")
    val_df = convert_rows(val_tasks, "val")

    train_path = args.output_dir / "train.parquet"
    val_path = args.output_dir / "val.parquet"
    train_df.to_parquet(train_path, index=False)
    val_df.to_parquet(val_path, index=False)

    print(f"Wrote {len(train_df)} train rows to {train_path}")
    print(f"Wrote {len(val_df)} val rows to {val_path}")


if __name__ == "__main__":
    main()
