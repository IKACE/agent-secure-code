#!/usr/bin/env python3
"""Evaluate CVE-Factory tasks using Docker containers.

Each CVE-Factory task ships with:
  - docker-compose.yaml + Dockerfile : vulnerable environment
  - tests/test_func.py              : correctness tests (should PASS before & after fix)
  - tests/test_vuln.py              : vulnerability tests (FAIL = vuln exists, PASS = fixed)
  - solution.sh                     : reference patch

Evaluation flow:
  1. Build & start the container (docker compose up)
  2. Copy the candidate solution into the container
  3. Run test_func (correctness) — must pass
  4. Run test_vuln (security)    — pass = fixed, fail = still vulnerable
  5. Tear down

Reward scheme (matches our dataset convention):
  0.0  — correctness fails or build error
  0.5  — correctness passes, security fails (vulnerability not fixed)
  1.0  — both pass (vulnerability fixed)

Usage:
  # Evaluate a single task with its reference solution:
  python evaluate_cve_factory.py data/cve_factory/cve_tasks/trainset-2/cve-2024-0241

  # Evaluate with a custom solution script:
  python evaluate_cve_factory.py data/cve_factory/cve_tasks/trainset-2/cve-2024-0241 --solution my_fix.sh

  # Evaluate all indexed tasks (from cve_factory_tasks.jsonl):
  python evaluate_cve_factory.py --all

  # Dry-run to check which tasks would be evaluated:
  python evaluate_cve_factory.py --all --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


SCRIPT_DIR = Path(__file__).parent
DEFAULT_INDEX = SCRIPT_DIR / "data" / "cve_factory_tasks.jsonl"

# Docker env vars that CVE-Factory's docker-compose.yaml expects
DOCKER_ENV_DEFAULTS = {
    "T_BENCH_TEST_DIR": "/workspace/tests",
    "T_BENCH_CONTAINER_LOGS_PATH": "/workspace/logs",
    "T_BENCH_CONTAINER_AGENT_LOGS_PATH": "/workspace/agent_logs",
}


def run_cmd(
    cmd: list[str],
    cwd: str | None = None,
    timeout: int = 300,
    env: dict | None = None,
) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)


def get_compose_project_name(task_dir: Path) -> str:
    """Deterministic compose project name from task path."""
    return f"cvefactory_{task_dir.name}".replace("-", "_")


def _make_compose_env(task_dir: Path) -> dict:
    """Build the env dict needed by docker compose for a task."""
    project = get_compose_project_name(task_dir)
    env = os.environ.copy()
    env.update(DOCKER_ENV_DEFAULTS)
    env["T_BENCH_TASK_DOCKER_CLIENT_IMAGE_NAME"] = f"{project}_client"
    env["T_BENCH_TASK_DOCKER_CLIENT_CONTAINER_NAME"] = f"{project}_client_1"

    logs_dir = task_dir / "logs"
    agent_logs_dir = task_dir / "agent_logs"
    logs_dir.mkdir(exist_ok=True)
    agent_logs_dir.mkdir(exist_ok=True)
    env["T_BENCH_TASK_LOGS_PATH"] = str(logs_dir)
    env["T_BENCH_TASK_AGENT_LOGS_PATH"] = str(agent_logs_dir)
    return env


def compose_up(task_dir: Path, build_timeout: int = 300) -> tuple[bool, str]:
    """Build and start the Docker environment for a task."""
    project = get_compose_project_name(task_dir)
    env = _make_compose_env(task_dir)

    rc, stdout, stderr = run_cmd(
        ["docker", "compose", "-p", project, "up", "-d", "--build"],
        cwd=str(task_dir),
        timeout=build_timeout,
        env=env,
    )

    if rc != 0:
        return False, f"docker compose up failed (rc={rc}):\n{stderr}"
    return True, stdout


def compose_down(task_dir: Path) -> None:
    """Tear down the Docker environment."""
    project = get_compose_project_name(task_dir)
    env = _make_compose_env(task_dir)

    subprocess.run(
        ["docker", "compose", "-p", project, "down", "-v", "--remove-orphans"],
        cwd=str(task_dir),
        capture_output=True,
        timeout=60,
        env=env,
    )


def get_container_name(task_dir: Path) -> str | None:
    """Find the running container name for a task."""
    project = get_compose_project_name(task_dir)
    env = _make_compose_env(task_dir)
    rc, stdout, _ = run_cmd(
        ["docker", "compose", "-p", project, "ps", "-q"],
        cwd=str(task_dir),
        env=env,
    )
    if rc == 0 and stdout.strip():
        container_id = stdout.strip().splitlines()[0]
        return container_id
    return None


def exec_in_container(container: str, cmd: str, timeout: int = 120) -> tuple[int, str, str]:
    """Execute a command inside a running container."""
    return run_cmd(
        ["docker", "exec", container, "bash", "-c", cmd],
        timeout=timeout,
    )


def copy_to_container(container: str, src: str, dst: str) -> bool:
    """Copy a file into the container."""
    rc, _, stderr = run_cmd(["docker", "cp", src, f"{container}:{dst}"])
    return rc == 0


def apply_solution(task_dir: Path, container: str, solution_path: Path | None = None) -> tuple[bool, str]:
    """Copy and run the solution script inside the container."""
    sol = solution_path or (task_dir / "solution.sh")
    if not sol.exists():
        return False, f"Solution not found: {sol}"

    if not copy_to_container(container, str(sol), "/workspace/solution.sh"):
        return False, "Failed to copy solution.sh into container"

    rc, stdout, stderr = exec_in_container(
        container, "chmod +x /workspace/solution.sh && /workspace/solution.sh", timeout=120
    )
    output = stdout + "\n" + stderr
    if rc != 0:
        return False, f"solution.sh failed (rc={rc}):\n{output}"
    return True, output


def run_tests_in_container(
    task_dir: Path, container: str, timeout: int = 120
) -> tuple[dict, str]:
    """Run test_func.py and test_vuln.py inside the container.

    Returns (results_dict, raw_output).
    """
    tests_dir = task_dir / "tests"

    # Copy tests into container
    copy_to_container(container, str(tests_dir), "/workspace/tests")

    # Install test dependencies (pytest, requests).
    # Try pip variants (some images have pip, some pip3, some need --break-system-packages).
    exec_in_container(
        container,
        "pip install pytest requests 2>/dev/null || "
        "pip3 install pytest requests 2>/dev/null || "
        "pip install pytest requests --break-system-packages 2>/dev/null || "
        "pip3 install pytest requests --break-system-packages 2>/dev/null || "
        "(apt-get update -qq && apt-get install -y -qq python3-pip >/dev/null 2>&1 && "
        "pip3 install pytest requests --break-system-packages 2>/dev/null) || "
        "true",
        timeout=120,
    )

    results = {"test_func": None, "test_vuln": None}
    raw_parts = []

    # Run test_func.py (correctness)
    rc_func, stdout_func, stderr_func = exec_in_container(
        container,
        "cd /workspace/tests && python3 -m pytest test_func.py -v --tb=short 2>&1",
        timeout=timeout,
    )
    raw_parts.append(f"=== test_func (rc={rc_func}) ===\n{stdout_func}\n{stderr_func}")
    results["test_func"] = "PASS" if rc_func == 0 else "FAIL"

    # Run test_vuln.py (security)
    rc_vuln, stdout_vuln, stderr_vuln = exec_in_container(
        container,
        "cd /workspace/tests && python3 -m pytest test_vuln.py -v --tb=short 2>&1",
        timeout=timeout,
    )
    raw_parts.append(f"=== test_vuln (rc={rc_vuln}) ===\n{stdout_vuln}\n{stderr_vuln}")
    results["test_vuln"] = "PASS" if rc_vuln == 0 else "FAIL"

    return results, "\n".join(raw_parts)


def compute_reward(test_results: dict) -> float:
    """Compute reward from test results.

    0.0 — correctness (test_func) fails
    0.5 — correctness passes, security (test_vuln) fails
    1.0 — both pass
    """
    if test_results.get("test_func") != "PASS":
        return 0.0
    if test_results.get("test_vuln") == "PASS":
        return 1.0
    return 0.5


def evaluate_task(
    task_dir: Path,
    solution_path: Path | None = None,
    build_timeout: int = 300,
    test_timeout: int = 120,
    keep_container: bool = False,
) -> dict:
    """Full evaluation of a single CVE-Factory task.

    1. docker compose up --build
    2. (optional) apply solution
    3. run tests
    4. docker compose down
    """
    task_dir = Path(task_dir).resolve()
    result = {
        "task_id": task_dir.name,
        "task_dir": str(task_dir),
        "build_ok": False,
        "solution_applied": False,
        "test_func": None,
        "test_vuln": None,
        "reward": 0.0,
        "error": None,
    }

    try:
        # Step 1: Build & start
        print(f"  Building {task_dir.name}...", file=sys.stderr)
        ok, msg = compose_up(task_dir, build_timeout=build_timeout)
        if not ok:
            result["error"] = msg
            return result
        result["build_ok"] = True

        # Wait for the container to be up and services to initialize
        container = None
        for _ in range(15):
            container = get_container_name(task_dir)
            if container:
                break
            time.sleep(2)
        if not container:
            result["error"] = "No running container found after compose up"
            return result

        # Give the service inside the container time to start (wait up to 30s)
        for _ in range(15):
            rc, stdout, _ = exec_in_container(container, "curl -sf http://localhost:3000/health 2>/dev/null || curl -sf http://localhost:8080/health 2>/dev/null || curl -sf http://localhost:80/ 2>/dev/null || echo __not_ready__", timeout=5)
            if rc == 0 and "__not_ready__" not in stdout:
                break
            time.sleep(2)

        # Step 2: Apply solution if provided
        if solution_path and solution_path.exists():
            sol_ok, sol_msg = apply_solution(task_dir, container, solution_path)
            result["solution_applied"] = sol_ok
            if not sol_ok:
                result["error"] = sol_msg
        elif not solution_path and (task_dir / "solution.sh").exists():
            sol_ok, sol_msg = apply_solution(task_dir, container)
            result["solution_applied"] = sol_ok
            if not sol_ok:
                result["error"] = sol_msg

        # Step 3: Run tests
        print(f"  Testing {task_dir.name}...", file=sys.stderr)
        test_results, raw = run_tests_in_container(task_dir, container, timeout=test_timeout)
        result["test_func"] = test_results.get("test_func")
        result["test_vuln"] = test_results.get("test_vuln")
        result["reward"] = compute_reward(test_results)

    except Exception as e:
        result["error"] = str(e)
    finally:
        if not keep_container:
            compose_down(task_dir)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("task_dir", nargs="?", help="Path to a CVE-Factory task directory")
    parser.add_argument("--solution", type=Path, help="Path to a custom solution.sh")
    parser.add_argument("--no-solution", action="store_true", help="Skip applying solution (test vulnerable state)")
    parser.add_argument("--all", action="store_true", help="Evaluate all tasks from the index")
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX, help="Path to cve_factory_tasks.jsonl")
    parser.add_argument("--split", choices=["trainset", "trainset-2"], help="Only evaluate tasks from this split")
    parser.add_argument("--limit", type=int, default=0, help="Max tasks to evaluate (0=all)")
    parser.add_argument("--build-timeout", type=int, default=300, help="Docker build timeout in seconds")
    parser.add_argument("--test-timeout", type=int, default=120, help="Test execution timeout in seconds")
    parser.add_argument("--keep", action="store_true", help="Keep containers after evaluation")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--dry-run", action="store_true", help="List tasks without running")
    args = parser.parse_args()

    if args.all:
        if not args.index.exists():
            print(
                f"Index not found: {args.index}\n"
                "Run: python cve_factory_adapter.py",
                file=sys.stderr,
            )
            sys.exit(1)

        with open(args.index) as f:
            tasks = [json.loads(line) for line in f]

        if args.split:
            tasks = [t for t in tasks if t["split"] == args.split]

        if args.limit > 0:
            tasks = tasks[: args.limit]

        if args.dry_run:
            for t in tasks:
                print(f"{t['task_id']}  ({t['difficulty']}, {t['category']})  tags={t['tags']}")
            print(f"\nTotal: {len(tasks)} tasks")
            return

        results = []
        for i, t in enumerate(tasks, 1):
            print(f"[{i}/{len(tasks)}] {t['task_id']}", file=sys.stderr)
            task_dir = Path(t["task_dir"])
            if not task_dir.is_dir():
                print(f"  SKIP: directory not found", file=sys.stderr)
                continue

            if args.no_solution:
                sol = Path("/nonexistent_sentinel")
            elif args.solution:
                sol = args.solution
            else:
                sol = None
            r = evaluate_task(
                task_dir,
                solution_path=sol,
                build_timeout=args.build_timeout,
                test_timeout=args.test_timeout,
                keep_container=args.keep,
            )
            r["cve_id"] = t.get("cve_id", "")
            r["split"] = t.get("split", "")
            results.append(r)

            reward_str = f"{r['reward']:.1f}"
            status = f"func={r['test_func']} vuln={r['test_vuln']} reward={reward_str}"
            if r["error"]:
                status += f" error={r['error'][:60]}"
            print(f"  -> {status}", file=sys.stderr)

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            _print_summary(results)

    elif args.task_dir:
        task_dir = Path(args.task_dir)
        if not task_dir.is_absolute():
            task_dir = Path.cwd() / task_dir

        # --no-solution: pass a sentinel so evaluate_task skips solution
        # --solution PATH: use custom solution
        # Neither: evaluate_task uses the default solution.sh in the task dir
        if args.no_solution:
            sol = Path("/nonexistent_sentinel")  # won't match .exists()
        elif args.solution:
            sol = args.solution
        else:
            sol = None

        r = evaluate_task(
            task_dir,
            solution_path=sol,
            build_timeout=args.build_timeout,
            test_timeout=args.test_timeout,
            keep_container=args.keep,
        )

        if args.json:
            print(json.dumps(r, indent=2))
        else:
            print(f"\nTask:     {r['task_id']}")
            print(f"Build:    {'OK' if r['build_ok'] else 'FAIL'}")
            print(f"Solution: {'applied' if r['solution_applied'] else 'skipped/failed'}")
            print(f"Func:     {r['test_func']}")
            print(f"Vuln:     {r['test_vuln']}")
            print(f"Reward:   {r['reward']:.1f}")
            if r["error"]:
                print(f"Error:    {r['error'][:200]}")
    else:
        parser.print_help()
        sys.exit(1)


def _print_summary(results: list[dict]) -> None:
    """Print a summary table of results."""
    print("\n" + "=" * 80)
    print(f"{'Task':<40} {'Build':>6} {'Func':>6} {'Vuln':>6} {'Reward':>7}")
    print("=" * 80)

    for r in results:
        name = r["task_id"][:38]
        build = "OK" if r["build_ok"] else "FAIL"
        func = r["test_func"] or "N/A"
        vuln = r["test_vuln"] or "N/A"
        reward = f"{r['reward']:.1f}"
        print(f"{name:<40} {build:>6} {func:>6} {vuln:>6} {reward:>7}")

    print("=" * 80)

    total = len(results)
    build_ok = sum(1 for r in results if r["build_ok"])
    func_pass = sum(1 for r in results if r["test_func"] == "PASS")
    vuln_pass = sum(1 for r in results if r["test_vuln"] == "PASS")
    avg_reward = sum(r["reward"] for r in results) / total if total else 0

    print(f"\nTotal: {total} tasks")
    print(f"  Build OK:    {build_ok}/{total}")
    print(f"  Func PASS:   {func_pass}/{total}")
    print(f"  Vuln PASS:   {vuln_pass}/{total}")
    print(f"  Avg reward:  {avg_reward:.2f}")


if __name__ == "__main__":
    main()
