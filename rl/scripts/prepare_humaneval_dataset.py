#!/usr/bin/env python3
"""Prepare a tiny verl-compatible coding dataset from HumanEval."""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import pandas as pd
from datasets import load_dataset


SYSTEM_PROMPT = (
    "You are given a Python function signature and docstring. "
    "Return only the function implementation in Python."
)


def build_prompt(problem_prompt: str) -> str:
    return (
        f"{SYSTEM_PROMPT}\n\n"
        "Write code that completes the following function.\n\n"
        f"{problem_prompt}"
    )


def convert_rows(rows: list[dict], split: str) -> pd.DataFrame:
    records = []
    for row in rows:
        records.append(
            {
                "data_source": "humaneval_codegen_random_reward",
                "prompt": build_prompt(row["prompt"]),
                "ground_truth": row["canonical_solution"],
                "reward_model": {"ground_truth": row["canonical_solution"]},
                "task_id": row["task_id"],
                "extra_info": {
                    "split": split,
                    "task_id": row["task_id"],
                    "entry_point": row["entry_point"],
                    "test": row["test"],
                    "original_prompt": row["prompt"],
                },
            }
        )
    return pd.DataFrame.from_records(records)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/humaneval"),
        help="Directory where train.parquet and val.parquet will be written.",
    )
    parser.add_argument(
        "--train-size",
        type=int,
        default=140,
        help="Number of HumanEval rows to place in train split.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=7,
        help="Seed for deterministic shuffling and splitting.",
    )
    args = parser.parse_args()

    ds = load_dataset("openai/openai_humaneval", split="test")
    rows = [dict(row) for row in ds]
    random.Random(args.seed).shuffle(rows)

    if args.train_size <= 0 or args.train_size >= len(rows):
        raise ValueError(
            f"--train-size must be between 1 and {len(rows) - 1}, got {args.train_size}"
        )

    train_rows = rows[: args.train_size]
    val_rows = rows[args.train_size :]

    args.output_dir.mkdir(parents=True, exist_ok=True)

    train_df = convert_rows(train_rows, split="train")
    val_df = convert_rows(val_rows, split="val")

    train_path = args.output_dir / "train.parquet"
    val_path = args.output_dir / "val.parquet"
    train_df.to_parquet(train_path, index=False)
    val_df.to_parquet(val_path, index=False)

    print(f"Wrote {len(train_df)} rows to {train_path}")
    print(f"Wrote {len(val_df)} rows to {val_path}")


if __name__ == "__main__":
    main()
