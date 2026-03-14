"""Reward function for CVE-Factory tasks (Docker-based evaluation).

Reward scheme:
  0.0 — build fails, or test_func (correctness) fails
  0.5 — test_func passes but test_vuln (security) fails (vulnerability not fixed)
  1.0 — both test_func and test_vuln pass (vulnerability fixed)

The model generates a solution.sh bash script. This reward function:
  1. Starts the vulnerable Docker environment (docker compose up)
  2. Copies the generated solution.sh into the container and executes it
  3. Runs test_func.py and test_vuln.py inside the container
  4. Tears down the container

Environment variables:
  TASK_DIR_REWRITE_FROM / TASK_DIR_REWRITE_TO — remap task_dir paths (for Docker)
  CVE_FACTORY_BUILD_TIMEOUT — docker build timeout in seconds (default: 300)
  CVE_FACTORY_TEST_TIMEOUT  — test execution timeout in seconds (default: 120)
  CVE_FACTORY_SERVICE_WAIT  — max seconds to wait for service readiness (default: 30)
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import time
from typing import Any

logger = logging.getLogger(__name__)

BUILD_TIMEOUT = int(os.environ.get("CVE_FACTORY_BUILD_TIMEOUT", "300"))
TEST_TIMEOUT = int(os.environ.get("CVE_FACTORY_TEST_TIMEOUT", "120"))
SERVICE_WAIT = int(os.environ.get("CVE_FACTORY_SERVICE_WAIT", "30"))

_TASK_DIR_REWRITE_FROM = os.environ.get("TASK_DIR_REWRITE_FROM", "")
_TASK_DIR_REWRITE_TO = os.environ.get("TASK_DIR_REWRITE_TO", "")

# Docker env vars expected by CVE-Factory's docker-compose.yaml
_DOCKER_ENV_DEFAULTS = {
    "T_BENCH_TEST_DIR": "/workspace/tests",
    "T_BENCH_CONTAINER_LOGS_PATH": "/workspace/logs",
    "T_BENCH_CONTAINER_AGENT_LOGS_PATH": "/workspace/agent_logs",
}


def _resolve_task_dir(task_dir: str) -> str:
    if _TASK_DIR_REWRITE_FROM and _TASK_DIR_REWRITE_TO:
        return task_dir.replace(_TASK_DIR_REWRITE_FROM, _TASK_DIR_REWRITE_TO)
    return task_dir


def _project_name(task_dir: str) -> str:
    return f"cvefactory_{os.path.basename(task_dir)}".replace("-", "_")


def _compose_env(task_dir: str) -> dict:
    project = _project_name(task_dir)
    env = os.environ.copy()
    env.update(_DOCKER_ENV_DEFAULTS)
    env["T_BENCH_TASK_DOCKER_CLIENT_IMAGE_NAME"] = f"{project}_client"
    env["T_BENCH_TASK_DOCKER_CLIENT_CONTAINER_NAME"] = f"{project}_client_1"
    logs = os.path.join(task_dir, "logs")
    agent_logs = os.path.join(task_dir, "agent_logs")
    os.makedirs(logs, exist_ok=True)
    os.makedirs(agent_logs, exist_ok=True)
    env["T_BENCH_TASK_LOGS_PATH"] = logs
    env["T_BENCH_TASK_AGENT_LOGS_PATH"] = agent_logs
    return env


def _run(cmd: list[str], cwd: str | None = None, timeout: int = 300,
         env: dict | None = None) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, env=env)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)


def _compose_up(task_dir: str) -> bool:
    project = _project_name(task_dir)
    env = _compose_env(task_dir)
    rc, _, stderr = _run(
        ["docker", "compose", "-p", project, "up", "-d", "--build"],
        cwd=task_dir, timeout=BUILD_TIMEOUT, env=env,
    )
    if rc != 0:
        logger.debug("compose up failed: %s", stderr[:200])
    return rc == 0


def _compose_down(task_dir: str) -> None:
    project = _project_name(task_dir)
    env = _compose_env(task_dir)
    _run(
        ["docker", "compose", "-p", project, "down", "-v", "--remove-orphans"],
        cwd=task_dir, timeout=60, env=env,
    )


def _get_container(task_dir: str) -> str | None:
    project = _project_name(task_dir)
    env = _compose_env(task_dir)
    rc, stdout, _ = _run(
        ["docker", "compose", "-p", project, "ps", "-q"],
        cwd=task_dir, env=env,
    )
    if rc == 0 and stdout.strip():
        return stdout.strip().splitlines()[0]
    return None


def _exec(container: str, cmd: str, timeout: int = 120) -> tuple[int, str, str]:
    return _run(["docker", "exec", container, "bash", "-c", cmd], timeout=timeout)


def _wait_for_container(task_dir: str) -> str | None:
    """Wait for the container to appear and return its ID."""
    for _ in range(15):
        c = _get_container(task_dir)
        if c:
            return c
        time.sleep(2)
    return None


def _wait_for_service(container: str) -> None:
    """Best-effort wait for the service inside the container."""
    for _ in range(SERVICE_WAIT // 2):
        rc, out, _ = _exec(
            container,
            "curl -sf http://localhost:3000/health 2>/dev/null || "
            "curl -sf http://localhost:8080/ 2>/dev/null || "
            "curl -sf http://localhost:80/ 2>/dev/null || "
            "echo __not_ready__",
            timeout=5,
        )
        if rc == 0 and "__not_ready__" not in out:
            return
        time.sleep(2)


def _install_test_deps(container: str) -> None:
    """Best-effort install pytest + requests inside the container."""
    _exec(
        container,
        "pip install pytest requests 2>/dev/null || "
        "pip3 install pytest requests 2>/dev/null || "
        "pip install pytest requests --break-system-packages 2>/dev/null || "
        "pip3 install pytest requests --break-system-packages 2>/dev/null || "
        "(apt-get update -qq && apt-get install -y -qq python3-pip >/dev/null 2>&1 && "
        "pip3 install pytest requests --break-system-packages 2>/dev/null) || true",
        timeout=120,
    )


def _extract_script(response: str) -> str:
    """Extract a bash script from model output."""
    # Try to find a fenced code block
    m = re.search(r"```(?:bash|sh)?\s*\n(.*?)```", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    # If response starts with shebang, use as-is
    if response.strip().startswith("#!/"):
        return response.strip()
    # Otherwise wrap in a script
    return "#!/bin/bash\nset -e\n" + response.strip()


def compute_score(
    data_source: str,
    solution_str: str,
    ground_truth: str,
    extra_info: dict[str, Any] | None = None,
) -> float:
    """Evaluate a generated solution.sh against a CVE-Factory task.

    Returns 0.0, 0.5, or 1.0.
    """
    if not extra_info:
        return 0.0

    task_dir = _resolve_task_dir(extra_info.get("task_dir", ""))
    if not task_dir or not os.path.isdir(task_dir):
        return 0.0

    script = _extract_script(solution_str)
    if not script:
        return 0.0

    # Write solution to a temp file
    try:
        fd, tmp_sol = tempfile.mkstemp(suffix=".sh", prefix="rl_sol_")
        os.write(fd, script.encode("utf-8"))
        os.close(fd)
        os.chmod(tmp_sol, 0o755)
    except OSError:
        return 0.0

    try:
        # 1. Build & start container
        if not _compose_up(task_dir):
            return 0.0

        container = _wait_for_container(task_dir)
        if not container:
            return 0.0

        _wait_for_service(container)

        # 2. Copy & run solution
        cp_rc, _, _ = _run(["docker", "cp", tmp_sol, f"{container}:/workspace/solution.sh"])
        if cp_rc != 0:
            return 0.0

        sol_rc, _, _ = _exec(container, "chmod +x /workspace/solution.sh && /workspace/solution.sh", timeout=120)
        # Don't bail on solution failure — still run tests to see partial credit

        # 3. Copy tests and install deps
        tests_dir = os.path.join(task_dir, "tests")
        _run(["docker", "cp", tests_dir, f"{container}:/workspace/tests"])
        _install_test_deps(container)

        # 4. Run test_func (correctness)
        rc_func, _, _ = _exec(
            container,
            "cd /workspace/tests && python3 -m pytest test_func.py -v --tb=short 2>&1",
            timeout=TEST_TIMEOUT,
        )
        if rc_func != 0:
            return 0.0

        # 5. Run test_vuln (security)
        rc_vuln, _, _ = _exec(
            container,
            "cd /workspace/tests && python3 -m pytest test_vuln.py -v --tb=short 2>&1",
            timeout=TEST_TIMEOUT,
        )
        if rc_vuln == 0:
            return 1.0
        return 0.5

    except Exception as e:
        logger.debug("reward error: %s", e)
        return 0.0
    finally:
        try:
            os.unlink(tmp_sol)
        except OSError:
            pass
        _compose_down(task_dir)
