#!/usr/bin/env python3
"""Prepare a verl-compatible dataset from secure-code task directories."""

from __future__ import annotations

import argparse
import difflib
import json
import random
import re
from collections import defaultdict
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


def _read_standalone(task_dir: Path) -> str:
    """Read the standalone (vulnerable) code file for a task."""
    for name in ("standalone.js", "standalone.py", "standalone.ts"):
        p = task_dir / name
        if p.exists():
            return p.read_text()
    return ""


def deduplicate(tasks: list[dict], similarity_threshold: float = 0.85) -> list[dict]:
    """Remove duplicate/near-duplicate tasks.

    Two dedup passes:
      1. Exact: same repo + sha + vuln_type + function + line → keep first only.
      2. Near: within same repo + sha + function, if standalone code similarity
         >= threshold, keep first only.
    """
    # --- Pass 1: exact metadata duplicates (path normalization issues) ---
    seen_exact: set[tuple] = set()
    after_exact = []
    exact_skipped = 0
    for t in tasks:
        task_dir = Path(t["task_dir"])
        tj_path = task_dir / "task.json"
        if tj_path.exists():
            tj = json.loads(tj_path.read_text())
            key = (
                tj.get("repo", ""),
                tj.get("sha", ""),
                tj.get("vuln_type", ""),
                tj.get("vuln_function_name", ""),
                str(tj.get("vuln_line", "")),
            )
        else:
            key = (t["task_id"],)

        if key in seen_exact:
            exact_skipped += 1
            continue
        seen_exact.add(key)
        after_exact.append(t)

    # --- Pass 2: near-duplicate standalone code within same function group ---
    by_group: dict[tuple, list[dict]] = defaultdict(list)
    for t in after_exact:
        task_dir = Path(t["task_dir"])
        tj_path = task_dir / "task.json"
        if tj_path.exists():
            tj = json.loads(tj_path.read_text())
            gkey = (tj.get("repo", ""), tj.get("sha", ""), tj.get("vuln_function_name", ""))
        else:
            gkey = (t["task_id"],)
        by_group[gkey].append(t)

    near_skipped = 0
    kept = []
    for gkey, group in by_group.items():
        if len(group) < 2:
            kept.extend(group)
            continue
        # Read standalone code for each
        codes = [_read_standalone(Path(t["task_dir"])) for t in group]
        kept_indices = [0]
        for i in range(1, len(group)):
            is_dup = False
            if codes[i]:
                for ki in kept_indices:
                    if codes[ki] and difflib.SequenceMatcher(None, codes[i], codes[ki]).ratio() >= similarity_threshold:
                        is_dup = True
                        break
            if is_dup:
                near_skipped += 1
            else:
                kept_indices.append(i)
        kept.extend(group[i] for i in kept_indices)

    if exact_skipped or near_skipped:
        print(f"Dedup: skipped {exact_skipped} exact duplicates, {near_skipped} near-duplicates")

    return kept


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
    parser.add_argument("--no-dedup", action="store_true", help="Skip deduplication")
    parser.add_argument("--dedup-threshold", type=float, default=0.85,
                        help="Similarity threshold for near-duplicate detection (default: 0.85)")
    args = parser.parse_args()

    tasks = load_tasks(args.tasks_dir)
    print(f"Loaded {len(tasks)} tasks from {args.tasks_dir}")

    if not args.no_dedup:
        tasks = deduplicate(tasks, similarity_threshold=args.dedup_threshold)
        print(f"After dedup: {len(tasks)} tasks")

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
