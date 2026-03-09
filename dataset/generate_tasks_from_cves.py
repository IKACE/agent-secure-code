#!/usr/bin/env python3
"""
Build tasks.jsonl from vibe-radar CVE data.

Reads vibe_radar_cves.jsonl, clones each repo at the bug-introducing commit's
parent, extracts diffs and file contents, and writes tasks in the same format
as generate_tasks.py (compatible with generate_prompts.py and run_evaluation.py).

Usage:
    python generate_tasks_from_cves.py \
        [--cves ../crawling/data/vibe_radar_cves.jsonl] \
        [--output data/tasks_cve.jsonl] \
        [--clone-root /tmp/cve_repos] \
        [--limit 0]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_CVES = Path(__file__).parent.parent / "crawling" / "data" / "vibe_radar_cves.jsonl"
DEFAULT_OUTPUT = Path(__file__).parent / "data" / "tasks_cve.jsonl"
DEFAULT_CLONE_ROOT = Path(os.getenv("CVE_CLONE_ROOT", "/tmp/cve_repos"))


def load_env() -> None:
    """Load .env file if present."""
    for env_path in [Path(__file__).parent / ".env",
                     Path(__file__).parent.parent / ".env"]:
        if not env_path.exists():
            continue
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key and value and key not in os.environ:
                os.environ[key] = value


def clone_repo(repo_slug: str, clone_root: Path) -> Optional[Path]:
    """Clone a GitHub repo if not already present. Returns repo path."""
    safe_name = repo_slug.replace("/", "__")
    repo_path = clone_root / safe_name
    if repo_path.exists() and (repo_path / ".git").exists():
        return repo_path

    repo_path.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{repo_slug}.git"
    try:
        r = subprocess.run(
            ["git", "clone", "--filter=blob:none", url, str(repo_path)],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            print(f"    [error] Clone failed: {r.stderr[:200]}", file=sys.stderr)
            shutil.rmtree(repo_path, ignore_errors=True)
            return None
        return repo_path
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"    [error] Clone error: {e}", file=sys.stderr)
        shutil.rmtree(repo_path, ignore_errors=True)
        return None


def git_parent_sha(repo_path: Path, sha: str) -> Optional[str]:
    """Get the parent commit SHA."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", f"{sha}^"],
            cwd=str(repo_path), capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def git_full_sha(repo_path: Path, short_sha: str) -> Optional[str]:
    """Resolve a short SHA to full SHA."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", short_sha],
            cwd=str(repo_path), capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def git_diff(repo_path: Path, parent_sha: str, sha: str) -> str:
    """Get the full diff between parent and commit."""
    try:
        r = subprocess.run(
            ["git", "diff", f"{parent_sha}..{sha}"],
            cwd=str(repo_path), capture_output=True, text=True, timeout=60,
        )
        return r.stdout if r.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def git_changed_files(repo_path: Path, parent_sha: str, sha: str) -> List[str]:
    """Get list of changed files between parent and commit."""
    try:
        r = subprocess.run(
            ["git", "diff", "--name-only", f"{parent_sha}..{sha}"],
            cwd=str(repo_path), capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            return [f for f in r.stdout.strip().split("\n") if f]
    except (subprocess.TimeoutExpired, OSError):
        pass
    return []


def git_show_file(repo_path: Path, sha: str, filepath: str) -> str:
    """Get file content at a specific commit."""
    try:
        r = subprocess.run(
            ["git", "show", f"{sha}:{filepath}"],
            cwd=str(repo_path), capture_output=True, text=True, timeout=30,
        )
        return r.stdout if r.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def git_commit_message(repo_path: Path, sha: str) -> str:
    """Get the commit message."""
    try:
        r = subprocess.run(
            ["git", "log", "-1", "--format=%B", sha],
            cwd=str(repo_path), capture_output=True, text=True, timeout=30,
        )
        return r.stdout.strip() if r.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def detect_language(changed_files: List[str]) -> str:
    """Detect primary language from file extensions."""
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "javascript",
        ".jsx": "javascript", ".tsx": "javascript", ".go": "go",
        ".java": "java", ".rb": "ruby", ".php": "php",
        ".rs": "rust", ".cs": "csharp", ".cpp": "cpp", ".c": "c",
        ".swift": "swift", ".kt": "kotlin", ".sol": "solidity",
    }
    ext_counts: Dict[str, int] = Counter()
    for f in changed_files:
        ext = Path(f).suffix.lower()
        if ext in ext_map:
            ext_counts[ext_map[ext]] += 1
    if ext_counts:
        return ext_counts.most_common(1)[0][0]
    return "unknown"


def cve_to_task(cve: Dict[str, Any], clone_root: Path) -> Optional[Dict[str, Any]]:
    """Convert a CVE record to a task record."""
    repo = cve.get("repo")
    if not repo:
        return None

    bug_commits = cve.get("bug_commits", [])
    if not bug_commits:
        return None

    # Use the first bug-introducing commit
    bug_commit = bug_commits[0]
    bug_url = bug_commit.get("url", "")
    short_sha = bug_commit.get("sha_short", "")

    if not bug_url or not short_sha:
        return None

    # Clone the repo
    repo_path = clone_repo(repo, clone_root)
    if repo_path is None:
        return None

    # Resolve full SHA
    full_sha = git_full_sha(repo_path, short_sha)
    if not full_sha:
        print(f"    [warn] Could not resolve SHA {short_sha}", file=sys.stderr)
        return None

    # Get parent SHA
    parent_sha = git_parent_sha(repo_path, full_sha)
    if not parent_sha:
        print(f"    [warn] No parent for {full_sha[:8]}", file=sys.stderr)
        return None

    # Get changed files and diff
    changed_files = git_changed_files(repo_path, parent_sha, full_sha)
    if not changed_files:
        return None

    diff = git_diff(repo_path, parent_sha, full_sha)
    if not diff:
        return None

    # Truncate very large diffs (>100KB)
    if len(diff) > 100_000:
        diff = diff[:100_000] + "\n... (truncated)"

    # Get commit message
    commit_message = git_commit_message(repo_path, full_sha)

    # Determine language
    language = detect_language(changed_files)

    # Get blamed file content at the commit
    blamed_file = bug_commit.get("blamed_file", "")
    vuln_files = [blamed_file] if blamed_file else changed_files[:5]

    file_contents = {}
    for vf in vuln_files:
        content = git_show_file(repo_path, full_sha, vf)
        if content:
            # Truncate very large files
            if len(content) > 50_000:
                content = content[:50_000] + "\n... (truncated)"
            file_contents[vf] = content

    # Map AI tool signals to agent names
    agents = []
    for sig in cve.get("ai_signals", {}).get("signals", []):
        tool = sig.get("tool", "").lower()
        if "copilot" in tool:
            agents.append("copilot")
        elif "claude" in tool:
            agents.append("claude_code")
        elif "aider" in tool:
            agents.append("aider")
        elif "roo" in tool:
            agents.append("roo_code")
        elif "cursor" in tool:
            agents.append("cursor")
        else:
            agents.append(tool)
    if not agents:
        # Fallback: check the CVE-level ai_tools if present
        for tool_name in cve.get("ai_tools", []):
            agents.append(tool_name)

    # Map CWEs to vulnerability type names
    cwe_to_vuln = {
        "CWE-22": "Path_traversal",
        "CWE-78": "Command_injection",
        "CWE-79": "Cross-site_scripting",
        "CWE-89": "SQL_injection",
        "CWE-94": "Code_injection",
        "CWE-116": "Improper_encoding_or_escaping_of_output",
        "CWE-200": "Information_exposure",
        "CWE-250": "Execution_with_unnecessary_privileges",
        "CWE-284": "Improper_access_control",
        "CWE-285": "Improper_authorization",
        "CWE-287": "Improper_authentication",
        "CWE-311": "Missing_encryption_of_sensitive_data",
        "CWE-312": "Clear_text_storage_of_sensitive_information",
        "CWE-319": "Cleartext_transmission_of_sensitive_information",
        "CWE-320": "Key_management_errors",
        "CWE-327": "Use_of_a_broken_or_risky_cryptographic_algorithm",
        "CWE-352": "Cross-site_request_forgery",
        "CWE-400": "Uncontrolled_resource_consumption",
        "CWE-434": "Unrestricted_upload_of_file_with_dangerous_type",
        "CWE-502": "Deserialization_of_untrusted_data",
        "CWE-522": "Insufficiently_protected_credentials",
        "CWE-601": "URL_redirection_to_untrusted_site",
        "CWE-611": "Improper_restriction_of_XML_external_entity_reference",
        "CWE-693": "Protection_mechanism_failure",
        "CWE-706": "Use_of_incorrectly-resolved_name_or_reference",
        "CWE-798": "Use_of_hard-coded_credentials",
        "CWE-862": "Missing_authorization",
        "CWE-863": "Incorrect_authorization",
        "CWE-918": "Server-side_request_forgery",
        "CWE-1321": "Improperly_controlled_modification_of_object_prototype_attributes",
    }

    vuln_types = []
    for cwe in cve.get("cwes", []):
        vt = cwe_to_vuln.get(cwe, cwe)
        vuln_types.append(vt)

    # Also use the causality_analysis vulnerability field if available
    ca = cve.get("causality_analysis", {})
    ca_vuln = ca.get("vulnerability", "")
    if ca_vuln and ca_vuln not in vuln_types:
        vuln_types.append(ca_vuln)

    repo_slug = repo.replace("/", "__")
    task_id = f"{repo_slug}__{full_sha[:8]}"

    return {
        "task_id": task_id,
        "source": "vibe_radar_cve",
        "cve_id": cve.get("cve_id") or cve.get("ghsa_id") or cve.get("id"),
        "repo_slug": repo_slug,
        "sha": full_sha,
        "parent_sha": parent_sha,
        "language": language,
        "agents": agents,
        "commit_message": commit_message,
        "changed_files": changed_files,
        "vuln_files": vuln_files,
        "vuln_types": vuln_types,
        "true_positives": 1,  # these are confirmed CVEs
        "severity": cve.get("severity"),
        "cvss": cve.get("cvss"),
        "cwes": cve.get("cwes", []),
        "root_cause": ca.get("root_cause", ""),
        "causal_chain": ca.get("causal_chain", ""),
        "diff": diff,
        "file_contents": file_contents,
        "prompt": None,
    }


def main() -> None:
    load_env()

    ap = argparse.ArgumentParser(description="Build tasks from vibe-radar CVE data")
    ap.add_argument("--cves", type=Path, default=DEFAULT_CVES,
                     help="Path to vibe_radar_cves.jsonl")
    ap.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                     help="Output JSONL file")
    ap.add_argument("--clone-root", type=Path, default=DEFAULT_CLONE_ROOT,
                     help="Directory to clone repos into")
    ap.add_argument("--limit", type=int, default=0,
                     help="Limit to N tasks (0 = all)")
    ap.add_argument("--dry-run", action="store_true",
                     help="Print stats without cloning or writing")
    args = ap.parse_args()

    if not args.cves.exists():
        print(f"[error] CVE file not found: {args.cves}", file=sys.stderr)
        sys.exit(1)

    # Load CVEs
    cves = []
    with open(args.cves, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cves.append(json.loads(line))
    print(f"Loaded {len(cves)} CVEs from {args.cves}", file=sys.stderr)

    if args.limit > 0:
        cves = cves[:args.limit]

    if args.dry_run:
        for cve in cves:
            repo = cve.get("repo", "?")
            bug = cve.get("bug_commits", [{}])[0].get("sha_short", "?")
            print(f"  {cve.get('id', '?'):30s}  {repo:40s}  {bug}")
        return

    args.clone_root.mkdir(parents=True, exist_ok=True)

    # Build tasks
    tasks = []
    skipped = Counter()
    for i, cve in enumerate(cves):
        cve_id = cve.get("id", "?")
        print(f"[{i+1}/{len(cves)}] {cve_id}...", file=sys.stderr, end=" ", flush=True)

        task = cve_to_task(cve, args.clone_root)
        if task is None:
            skipped["no_repo_or_commit"] += 1
            print("SKIP", file=sys.stderr)
            continue

        if not task["diff"]:
            skipped["no_diff"] += 1
            print("SKIP (no diff)", file=sys.stderr)
            continue

        tasks.append(task)
        print(f"OK ({task['language']}, {len(task['changed_files'])} files)", file=sys.stderr)

    print(f"\nBuilt {len(tasks)} tasks. Skipped: {dict(skipped)}", file=sys.stderr)

    # Stats
    lang_counts = Counter(t["language"] for t in tasks)
    agent_counts = Counter(a for t in tasks for a in t["agents"])
    sev_counts = Counter(t.get("severity", "?") for t in tasks)

    print(f"\n--- Task Statistics ---", file=sys.stderr)
    print(f"Total tasks: {len(tasks)}", file=sys.stderr)
    print(f"\nLanguages:", file=sys.stderr)
    for lang, cnt in lang_counts.most_common():
        print(f"  {lang}: {cnt}", file=sys.stderr)
    print(f"\nAgents:", file=sys.stderr)
    for agent, cnt in agent_counts.most_common():
        print(f"  {agent}: {cnt}", file=sys.stderr)
    print(f"\nSeverity:", file=sys.stderr)
    for sev, cnt in sev_counts.most_common():
        print(f"  {sev}: {cnt}", file=sys.stderr)

    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for task in tasks:
            f.write(json.dumps(task, ensure_ascii=False) + "\n")
    print(f"\nWrote {len(tasks)} tasks to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
