"""Simulated binary reward for verl PPO smoke tests."""

from __future__ import annotations

import hashlib
import os
import random
from typing import Any


def _stable_binary_reward(solution_str: str, extra_info: dict[str, Any] | None) -> float:
    seed_prefix = os.environ.get("RANDOM_REWARD_SEED", "0")
    task_id = ""
    if extra_info:
        task_id = str(extra_info.get("task_id", ""))

    payload = f"{seed_prefix}::{task_id}::{solution_str}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    rng = random.Random(int(digest[:16], 16))
    return float(rng.randint(0, 1))


def compute_score(
    data_source: str,
    solution_str: str,
    ground_truth: str,
    extra_info: dict[str, Any] | None = None,
) -> float:
    """Return a deterministic pseudo-random binary reward.

    `verl` expects the reward hook to accept
    `(data_source, solution_str, ground_truth, extra_info=None)`.
    The arguments are kept even when unused so this file can be swapped with a
    real evaluator later without changing the trainer wiring.
    """

    del data_source
    del ground_truth
    return _stable_binary_reward(solution_str=solution_str, extra_info=extra_info)
