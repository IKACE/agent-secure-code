"""Reward function for secure code generation RL training.

Reward scheme:
  - 0.0  if correctness tests fail
  - 0.5  if correctness tests pass but security tests fail (vulnerable)
  - 1.0  if both correctness and security tests pass (correct + secure)
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from typing import Any

logger = logging.getLogger(__name__)

# Timeout for each test execution (seconds)
TEST_TIMEOUT = int(os.environ.get("SECURE_CODE_TEST_TIMEOUT", "10"))

# How many reward calls to log in detail (set REWARD_DEBUG_LOG_COUNT>0 to debug)
_DEBUG_LOG_COUNT = int(os.environ.get("REWARD_DEBUG_LOG_COUNT", "0"))
_call_counter = 0

# Base path for task directories - adjust if running inside Docker
# The container mounts /raid/yilegu -> /workspace/verl
_TASK_DIR_REWRITE_FROM = os.environ.get("TASK_DIR_REWRITE_FROM", "")
_TASK_DIR_REWRITE_TO = os.environ.get("TASK_DIR_REWRITE_TO", "")


def _resolve_task_dir(task_dir: str) -> str:
    """Rewrite task_dir path if running inside Docker with different mount."""
    if _TASK_DIR_REWRITE_FROM and _TASK_DIR_REWRITE_TO:
        return task_dir.replace(_TASK_DIR_REWRITE_FROM, _TASK_DIR_REWRITE_TO)
    return task_dir


def _extract_code_from_response(response: str, language: str) -> str:
    """Extract code from model response, stripping markdown fences and explanation."""
    # Try to extract code from markdown code blocks
    lang_tags = ["js", "javascript", "py", "python", "ts", "typescript", ""]
    for tag in lang_tags:
        pattern = rf"```{tag}\s*\n(.*?)```"
        matches = re.findall(pattern, response, re.DOTALL)
        if matches:
            # Use the longest code block (likely the main implementation)
            return max(matches, key=len).strip()

    # No code fences found - use the raw response
    return response.strip()


def _assemble_code(setup_code: str, func_signature: str, solution: str, language: str) -> str:
    """Assemble a complete runnable file from setup code + model output."""
    code = _extract_code_from_response(solution, language)

    # Heuristic: if the code already includes typical setup indicators,
    # assume it's a complete file
    if language == "javascript":
        has_setup = ("require(" in code or "import " in code)
    else:
        has_setup = ("import " in code or "from " in code)

    if has_setup and len(code) > len(setup_code) * 0.5:
        return code

    # Otherwise, assemble: setup_code + func_signature + model_output
    parts = [setup_code]
    if func_signature:
        parts.append(func_signature)
    parts.append(code)
    return "\n\n".join(parts)


def _run_test(test_path: str, impl_path: str, language: str) -> int:
    """Run a test file against an implementation. Returns exit code."""
    if language == "javascript":
        cmd = ["node", test_path, impl_path]
    else:
        cmd = ["python3", test_path, impl_path]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=TEST_TIMEOUT,
            cwd=os.path.dirname(test_path),
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        return -1
    except Exception:
        return -1


def compute_score(
    data_source: str,
    solution_str: str,
    ground_truth: str,
    extra_info: dict[str, Any] | None = None,
) -> float:
    """Compute reward for a generated code solution.

    Returns:
        0.0 - correctness tests fail
        0.5 - correctness passes, security fails (vulnerable but functional)
        1.0 - both correctness and security pass (correct and secure)
    """
    global _call_counter
    _call_counter += 1
    debug = _call_counter <= _DEBUG_LOG_COUNT

    if extra_info is None:
        if debug:
            print(f"[REWARD DEBUG #{_call_counter}] extra_info is None, returning 0.0")
        return 0.0

    task_dir = _resolve_task_dir(extra_info.get("task_dir", ""))
    language = extra_info.get("language", "javascript")
    setup_code = extra_info.get("setup_code", "")
    func_signature = extra_info.get("func_signature", "")

    if debug:
        print(f"[REWARD DEBUG #{_call_counter}] task_dir={task_dir}, language={language}, "
              f"setup_code_len={len(setup_code)}, solution_len={len(solution_str)}")
        print(f"[REWARD DEBUG #{_call_counter}] solution_str[:200]={solution_str[:200]!r}")

    if not task_dir or not os.path.isdir(task_dir):
        if debug:
            print(f"[REWARD DEBUG #{_call_counter}] task_dir missing or not a dir: {task_dir!r}")
        return 0.0

    ext = ".js" if language == "javascript" else ".py"
    tests_dir = os.path.join(task_dir, "tests")

    correctness_test = os.path.join(tests_dir, f"test_correctness{ext}")
    security_test = os.path.join(tests_dir, f"test_security{ext}")

    if not os.path.exists(correctness_test):
        return 0.0

    # Assemble the full implementation file
    full_code = _assemble_code(setup_code, func_signature, solution_str, language)

    # Write to temp file
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, prefix="rl_eval_", delete=False
        ) as f:
            f.write(full_code)
            tmp_path = f.name

        # Run correctness test
        rc = _run_test(correctness_test, tmp_path, language)
        if debug:
            print(f"[REWARD DEBUG #{_call_counter}] correctness rc={rc}, file={tmp_path}")
        if rc != 0:
            return 0.0

        # Correctness passed - run security test
        if os.path.exists(security_test):
            rc = _run_test(security_test, tmp_path, language)
            if debug:
                print(f"[REWARD DEBUG #{_call_counter}] security rc={rc}")
            if rc == 0:
                return 1.0  # Both pass: correct + secure
            else:
                return 0.5  # Correct but vulnerable
        else:
            # No security test available, treat correct code as full reward
            return 1.0

    except Exception:
        return 0.0
    finally:
        try:
            os.unlink(tmp_path)
        except (OSError, UnboundLocalError):
            pass
