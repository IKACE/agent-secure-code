#!/usr/bin/env python3
"""
Stars-first repo discovery (NO total_count), then scan commits for STRICT AI attribution markers,
optionally fetch per-commit diffs.

Adds:
  - Timestamp window logic: record newest_scanned_time / oldest_scanned_time (for the first X pages).
    If on a later run the first X pages fall fully inside the stored window, skip the repo scan.
  - Crash-resume skip: --skip-if-scanned skips repos already present in out/scan_done.jsonl.
    (Use together with --force-rescan to override.)

Discovery strategy (unchanged):
- Use fixed star buckets and GitHub Search API sort=stars desc.
- For each bucket, fetch at most 10 pages (<=1000 results) to avoid 422.
- No /search/... total_count calls.

Outputs:
  out/
    repos.jsonl
    repos.state.json
    scan_done.jsonl            # crash-resume marker (append-only)
    scan_state.json            # newest/oldest scanned time per repo (small JSON map)
    repos/
      owner__repo/             # created ONLY if repo has >=1 matched AI commit
        commits.jsonl
        state.json             # per-repo scan metadata (newest/oldest, etc.)
        summary.json
        diffs/
          <sha>.json
        diffs.state.json
        
Usage:
python3 crawl_ai_commits_at_scale.py --outdir output --min-stars 1000 --max-repos 1000       --scan-pages-per-repo 100 --fetch-diffs --max-diffs-per-repo 100

AI-only co-author mode (global commit search, no star sorting):
python3 crawl_ai_commits_at_scale.py --mode ai-coauthor-only --outdir output_ai_only       --ai-search-pages-per-query 10
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests


# ---------------- Strict attribution patterns ----------------
STRICT_PATTERNS = {
    "claude": [
        r"\bGenerated with\s+\[?Claude Code\]?\b",
        r"^Co-authored-by:\s*Claude\s*<noreply@anthropic\.com>$",
    ],
    "gemini": [
        r"\bGenerated with\s+\[?Gemini CLI\]?\b",
        r"^Co-authored-by:\s*Gemini\s*<noreply@google\.com>$",
    ],
    "copilot": [
        r"\bGenerated with\s+GitHub Copilot\b",
        r"^Co-authored-by:\s*GitHub Copilot\s*<noreply@github\.com>$",
    ],
    "codex": [
        r"^Co-authored-by:\s*Codex\s*<codex@openai\.com>$",
    ],
}
COMPILED = {
    agent: [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in pats]
    for agent, pats in STRICT_PATTERNS.items()
}

AI_COAUTHOR_IDENTITIES = {
    "claude": {"name": "Claude", "email": "noreply@anthropic.com"},
    "gemini": {"name": "Gemini", "email": "noreply@google.com"},
    "copilot": {"name": "GitHub Copilot", "email": "noreply@github.com"},
    "codex": {"name": "Codex", "email": "codex@openai.com"},
}
AI_EMAIL_TO_AGENT = {
    v["email"].lower(): k for k, v in AI_COAUTHOR_IDENTITIES.items()
}
COAUTHORED_BY_RE = re.compile(
    r"^Co-authored-by:\s*(?P<name>.+?)\s*<(?P<email>[^>]+)>\s*$",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------- GitHub API helpers ----------------
def github_session(token: Optional[str]) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Accept": "application/vnd.github+json",
        "User-Agent": "ai-commit-crawler/stars-window-skip-v1",
    })
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def request_with_retry(sess: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    for attempt in range(10):
        r = sess.request(method, url, timeout=45, **kwargs)

        if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
            reset = int(r.headers.get("X-RateLimit-Reset", "0"))
            sleep_s = max(1, reset - int(time.time()) + 2)
            print(f"[rate-limit] sleeping {sleep_s}s", file=sys.stderr)
            time.sleep(sleep_s)
            continue

        if r.status_code == 403 and "rate limit" in (r.text or "").lower():
            time.sleep(2.0 * (attempt + 1))
            continue

        if r.status_code >= 500:
            time.sleep(1.5 * (attempt + 1))
            continue

        return r

    return r


# ---------------- JSON helpers ----------------
def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


# ---------------- Time helpers ----------------
def parse_iso8601(s: str) -> Optional[datetime]:
    if not s:
        return None
    # GitHub uses Z suffix
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        return datetime.fromisoformat(s)
    except Exception:
        return None


def to_iso_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------- Crash-resume scan marker ----------------
def load_scanned_repos(scan_done_jsonl: Path) -> Set[str]:
    scanned: Set[str] = set()
    if not scan_done_jsonl.exists():
        return scanned
    with scan_done_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                repo = obj.get("repo")
                if repo:
                    scanned.add(repo)
            except json.JSONDecodeError:
                continue
    return scanned


def mark_repo_scanned(scan_done_jsonl: Path, repo_full: str) -> None:
    append_jsonl(scan_done_jsonl, {
        "repo": repo_full,
        "scanned_at": to_iso_z(datetime.now(timezone.utc)),
    })


# ---------------- Discovery: fixed star buckets, <= 10 pages each ----------------
def star_buckets(min_stars: int) -> List[Tuple[int, Optional[int]]]:
    buckets = [
        (50000, None),
        (20000, 49999),
        (10000, 19999),
        (5000, 9999),
        (2000, 4999),
        (1000, 1999),
        (500, 999),
        (200, 499),
        (100, 199),
        (50, 99),
        (20, 49),
        (10, 19),
        (5, 9),
        (1, 4),
    ]
    out: List[Tuple[int, Optional[int]]] = []
    for lo, hi in buckets:
        if hi is None:
            if lo >= min_stars:
                out.append((lo, None))
        else:
            if hi >= min_stars:
                out.append((max(lo, min_stars), hi))
    return out


def repo_search(sess: requests.Session, q: str, page: int, per_page: int = 100) -> Dict[str, Any]:
    url = "https://api.github.com/search/repositories"
    r = request_with_retry(sess, "GET", url, params={
        "q": q,
        "sort": "stars",
        "order": "desc",
        "page": page,
        "per_page": per_page,
    })
    if r.status_code == 422:
        return {"items": []}
    if r.status_code != 200:
        raise RuntimeError(f"repo search failed: {r.status_code} {r.text[:300]}")
    return r.json()


def load_seen_repos(repos_jsonl: Path) -> Set[str]:
    seen: Set[str] = set()
    if not repos_jsonl.exists():
        return seen
    with repos_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
                full = obj.get("full_name")
                if full:
                    seen.add(full)
            except json.JSONDecodeError:
                continue
    return seen


def discover_repos_stars(
    sess: requests.Session,
    outdir: Path,
    min_stars: int,
    max_repos: int,
    search_sleep: float,
) -> None:
    repos_jsonl = outdir / "repos.jsonl"
    state_path = outdir / "repos.state.json"

    outdir.mkdir(parents=True, exist_ok=True)
    seen = load_seen_repos(repos_jsonl)

    buckets = star_buckets(min_stars)
    state = load_json(state_path, default={"bucket_idx": 0, "page": 1})

    for bidx in range(int(state["bucket_idx"]), len(buckets)):
        lo, hi = buckets[bidx]
        q = f"stars:>={lo}" if hi is None else f"stars:{lo}..{hi}"

        start_page = int(state["page"]) if bidx == int(state["bucket_idx"]) else 1

        for page in range(start_page, 11):
            if len(seen) >= max_repos:
                save_json(state_path, {"bucket_idx": bidx, "page": page})
                return

            data = repo_search(sess, q=q, page=page, per_page=100)
            items = data.get("items") or []
            if not items:
                save_json(state_path, {"bucket_idx": bidx, "page": page})
                break

            for it in items:
                full = it.get("full_name")
                if not full or full in seen:
                    continue
                rec = {
                    "full_name": full,
                    "stargazers_count": it.get("stargazers_count"),
                    "html_url": it.get("html_url"),
                    "pushed_at": it.get("pushed_at"),
                    "created_at": it.get("created_at"),
                    "language": it.get("language"),
                    "fork": it.get("fork"),
                    "archived": it.get("archived"),
                }
                append_jsonl(repos_jsonl, rec)
                seen.add(full)

                if len(seen) >= max_repos:
                    save_json(state_path, {"bucket_idx": bidx, "page": page})
                    return

            save_json(state_path, {"bucket_idx": bidx, "page": page + 1})
            if search_sleep > 0:
                time.sleep(search_sleep)

        save_json(state_path, {"bucket_idx": bidx + 1, "page": 1})


# ---------------- Scanning commits (create repo dir ONLY if match exists) ----------------
def slug(repo_full: str) -> str:
    owner, name = repo_full.split("/", 1)
    return f"{owner}__{name}"


def list_commits_page(sess: requests.Session, owner: str, repo: str, page: int, per_page: int = 100) -> List[Dict[str, Any]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    r = request_with_retry(sess, "GET", url, params={"page": page, "per_page": per_page})
    if r.status_code == 409:
        return []
    if r.status_code != 200:
        raise RuntimeError(f"list commits failed {owner}/{repo} page={page}: {r.status_code} {r.text[:200]}")
    return r.json()


def search_commits_page(
    sess: requests.Session,
    q: str,
    page: int,
    per_page: int = 100,
) -> Dict[str, Any]:
    url = "https://api.github.com/search/commits"
    r = request_with_retry(
        sess,
        "GET",
        url,
        params={
            "q": q,
            "sort": "committer-date",
            "order": "desc",
            "page": page,
            "per_page": per_page,
        },
        headers={"Accept": "application/vnd.github.cloak-preview+json"},
    )
    if r.status_code == 422:
        return {"items": []}
    if r.status_code != 200:
        raise RuntimeError(f"commit search failed: {r.status_code} {r.text[:300]}")
    return r.json()


def match_agents(msg: str) -> Tuple[List[str], List[Dict[str, str]]]:
    agents: Set[str] = set()
    matches: List[Dict[str, str]] = []
    for agent, regs in COMPILED.items():
        for reg in regs:
            if reg.search(msg):
                agents.add(agent)
                matches.append({"agent": agent, "pattern": reg.pattern})
                break
    return sorted(agents), matches


def parse_coauthors(msg: str) -> List[Dict[str, str]]:
    coauthors: List[Dict[str, str]] = []
    for m in COAUTHORED_BY_RE.finditer(msg or ""):
        name = (m.group("name") or "").strip()
        email = (m.group("email") or "").strip().lower()
        coauthors.append({"name": name, "email": email})
    return coauthors


def ai_coauthor_info(msg: str) -> Dict[str, Any]:
    coauthors = parse_coauthors(msg)
    if not coauthors:
        return {"coauthors": [], "agents": [], "ai_only": False}

    agents: Set[str] = set()
    all_ai = True
    for c in coauthors:
        agent = AI_EMAIL_TO_AGENT.get(c["email"])
        if agent:
            agents.add(agent)
        else:
            all_ai = False

    ai_only = len(agents) > 0 and all_ai
    return {
        "coauthors": coauthors,
        "agents": sorted(agents),
        "ai_only": ai_only,
    }


def load_seen_shas(jsonl_path: Path) -> Set[str]:
    seen: Set[str] = set()
    if not jsonl_path.exists():
        return seen
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
                sha = obj.get("sha")
                if sha:
                    seen.add(sha)
            except json.JSONDecodeError:
                continue
    return seen


def update_scan_state_window(
    scan_state: Dict[str, Any],
    repo_full: str,
    window_newest: datetime,
    window_oldest: datetime,
    pages_scanned: int,
) -> None:
    prev = scan_state.get(repo_full) or {}
    prev_newest = parse_iso8601(prev.get("newest_scanned_time") or "")
    prev_oldest = parse_iso8601(prev.get("oldest_scanned_time") or "")

    newest = window_newest if prev_newest is None else max(prev_newest, window_newest)
    oldest = window_oldest if prev_oldest is None else min(prev_oldest, window_oldest)

    scan_state[repo_full] = {
        "newest_scanned_time": to_iso_z(newest),
        "oldest_scanned_time": to_iso_z(oldest),
        "last_run_pages": pages_scanned,
        "last_run_at": to_iso_z(datetime.now(timezone.utc)),
    }


def window_is_covered(scan_state: Dict[str, Any], repo_full: str, window_newest: datetime, window_oldest: datetime) -> bool:
    prev = scan_state.get(repo_full)
    if not prev:
        return False
    prev_newest = parse_iso8601(prev.get("newest_scanned_time") or "")
    prev_oldest = parse_iso8601(prev.get("oldest_scanned_time") or "")
    if prev_newest is None or prev_oldest is None:
        return False
    # covered if current window is fully inside previously scanned interval
    return (window_newest <= prev_newest) and (window_oldest >= prev_oldest)


def scan_repo_commits(
    sess: requests.Session,
    outdir: Path,
    repo_full: str,
    max_pages: int,
    scan_state_path: Path,
    scan_done_jsonl: Path,
    scanned_repos_cache: Set[str],
    skip_if_scanned: bool,
    force_rescan: bool,
) -> None:
    # Crash-resume skip ONLY: if repo already in scan_done.jsonl, skip unless force_rescan
    if skip_if_scanned and (not force_rescan) and (repo_full in scanned_repos_cache):
        print(f"[scan] {repo_full} skip_if_scanned hit, skipping", file=sys.stderr)
        return

    owner, name = repo_full.split("/", 1)
    repo_slug = slug(repo_full)

    # Only create repo_dir if we find at least one match.
    repo_dir = outdir / "repos" / repo_slug
    commits_jsonl = repo_dir / "commits.jsonl"
    summary_path = repo_dir / "summary.json"
    state_path = repo_dir / "state.json"

    # Dedup for matched commits only (as before)
    seen_matched_shas = load_seen_shas(commits_jsonl) if repo_dir.exists() else set()

    # Load global scan_state.json (small map)
    scan_state = load_json(scan_state_path, default={})

    # Step 1: Fetch first X pages and collect window times (cheap metadata)
    window_times: List[datetime] = []
    pages_scanned = 0

    for page in range(1, max_pages + 1):
        items = list_commits_page(sess, owner, name, page=page, per_page=100)
        if not items:
            break
        pages_scanned += 1
        for it in items:
            commit = it.get("commit") or {}
            committer_meta = (commit.get("committer") or {})
            t = committer_meta.get("date") or ""
            dt = parse_iso8601(t)
            if dt is not None:
                window_times.append(dt)

    if not window_times:
        # still mark scanned for crash-resume semantics
        mark_repo_scanned(scan_done_jsonl, repo_full)
        scanned_repos_cache.add(repo_full)
        print(f"[scan] {repo_full} no commits (or cannot parse), done", file=sys.stderr)
        return

    window_newest = max(window_times)
    window_oldest = min(window_times)

    # Step 2: If window covered, skip actual scanning & writing
    if (not force_rescan) and window_is_covered(scan_state, repo_full, window_newest, window_oldest):
        mark_repo_scanned(scan_done_jsonl, repo_full)
        scanned_repos_cache.add(repo_full)
        print(
            f"[scan] {repo_full} window covered ({to_iso_z(window_oldest)}..{to_iso_z(window_newest)}), skipping",
            file=sys.stderr
        )
        return

    # Step 3: Actually scan the same first X pages for AI markers
    scanned = 0
    matched_new = 0
    any_match_ever = repo_dir.exists() and commits_jsonl.exists()

    for page in range(1, max_pages + 1):
        items = list_commits_page(sess, owner, name, page=page, per_page=100)
        if not items:
            break

        for it in items:
            scanned += 1
            sha = it.get("sha")
            if not sha:
                continue

            commit = it.get("commit") or {}
            msg = (commit.get("message") or "").strip()
            agents, matches = match_agents(msg)
            if not agents:
                continue

            if sha in seen_matched_shas:
                continue

            # First match => create repo dir
            if not any_match_ever:
                repo_dir.mkdir(parents=True, exist_ok=True)
                any_match_ever = True

            author_user = it.get("author") or {}
            committer_user = it.get("committer") or {}
            author_meta = (commit.get("author") or {})
            committer_meta = (commit.get("committer") or {})

            row = {
                "repo": repo_full,
                "sha": sha,
                "html_url": it.get("html_url"),
                "commit_message": msg,
                "commit_time": (committer_meta.get("date") or ""),
                "agents": agents,
                "confidence": "strict",
                "signals": {"matched_patterns": matches},
                "author": {
                    "login": author_user.get("login") or "",
                    "name": author_meta.get("name") or "",
                    "email": author_meta.get("email") or "",
                },
                "committer": {
                    "login": committer_user.get("login") or "",
                    "name": committer_meta.get("name") or "",
                    "email": committer_meta.get("email") or "",
                },
            }
            append_jsonl(commits_jsonl, row)
            seen_matched_shas.add(sha)
            matched_new += 1

    # Step 4: Update scan_state.json (global newest/oldest) regardless of whether we found AI commits
    update_scan_state_window(scan_state, repo_full, window_newest, window_oldest, pages_scanned=pages_scanned)
    save_json(scan_state_path, scan_state)

    # Step 5: Per-repo metadata & summary only if we created repo dir (i.e., any AI match ever)
    if any_match_ever:
        # Persist per-repo state metadata (useful for debugging)
        save_json(state_path, {
            "repo": repo_full,
            "window_pages": max_pages,
            "pages_scanned": pages_scanned,
            "window_newest": to_iso_z(window_newest),
            "window_oldest": to_iso_z(window_oldest),
            "last_run_at": to_iso_z(datetime.now(timezone.utc)),
        })

        # Rebuild summary.json from commits.jsonl (only matched commits)
        commits: List[Dict[str, Any]] = []
        if commits_jsonl.exists():
            with commits_jsonl.open("r", encoding="utf-8") as f:
                for line in f:
                    try:
                        commits.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        summary = {
            "repo": repo_full,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "num_commits": len(commits),
            "commits": commits,
        }
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    # Step 6: crash-resume marker
    mark_repo_scanned(scan_done_jsonl, repo_full)
    scanned_repos_cache.add(repo_full)

    print(
        f"[scan] {repo_full} scanned={scanned} matched_new={matched_new} "
        f"window=({to_iso_z(window_oldest)}..{to_iso_z(window_newest)}) any_match={any_match_ever}",
        file=sys.stderr
    )


# ---------------- Diff fetch (unchanged) ----------------
def read_matched_shas(commits_jsonl: Path) -> List[str]:
    shas: List[str] = []
    if not commits_jsonl.exists():
        return shas
    with commits_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
                sha = obj.get("sha")
                if sha:
                    shas.append(sha)
            except json.JSONDecodeError:
                continue
    return shas


def get_commit_detail(sess: requests.Session, owner: str, repo: str, sha: str) -> Dict[str, Any]:
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    r = request_with_retry(sess, "GET", url)
    if r.status_code != 200:
        raise RuntimeError(f"commit detail failed {owner}/{repo} sha={sha}: {r.status_code} {r.text[:200]}")
    return r.json()


def fetch_repo_diffs(sess: requests.Session, outdir: Path, repo_full: str, max_diffs_per_repo: int) -> None:
    repo_slug = slug(repo_full)
    repo_dir = outdir / "repos" / repo_slug
    commits_jsonl = repo_dir / "commits.jsonl"
    if not commits_jsonl.exists():
        return

    owner, name = repo_full.split("/", 1)
    diffs_dir = repo_dir / "diffs"
    diffs_dir.mkdir(parents=True, exist_ok=True)
    diffs_state_path = repo_dir / "diffs.state.json"

    state = load_json(diffs_state_path, default={"done_shas": [], "next_idx": 0})
    done: Set[str] = set(state.get("done_shas") or [])
    next_idx = int(state.get("next_idx", 0))

    shas = read_matched_shas(commits_jsonl)

    fetched = 0
    for i in range(next_idx, len(shas)):
        sha = shas[i]
        if sha in done:
            continue

        out_path = diffs_dir / f"{sha}.json"
        if out_path.exists():
            done.add(sha)
            save_json(diffs_state_path, {"done_shas": sorted(done), "next_idx": i + 1})
            continue

        detail = get_commit_detail(sess, owner, name, sha)

        files_out: List[Dict[str, Any]] = []
        for fi in (detail.get("files") or []):
            files_out.append({
                "filename": fi.get("filename"),
                "status": fi.get("status"),
                "additions": fi.get("additions"),
                "deletions": fi.get("deletions"),
                "changes": fi.get("changes"),
                "patch": fi.get("patch"),
                "raw_url": fi.get("raw_url"),
                "blob_url": fi.get("blob_url"),
            })

        rec = {
            "repo": repo_full,
            "sha": sha,
            "html_url": detail.get("html_url"),
            "stats": detail.get("stats"),
            "commit": {
                "message": ((detail.get("commit") or {}).get("message") or ""),
                "author": (detail.get("commit") or {}).get("author") or {},
                "committer": (detail.get("commit") or {}).get("committer") or {},
            },
            "files": files_out,
        }
        save_json(out_path, rec)

        done.add(sha)
        fetched += 1
        save_json(diffs_state_path, {"done_shas": sorted(done), "next_idx": i + 1})

        if fetched >= max_diffs_per_repo:
            break

    print(f"[diffs] {repo_full} fetched_new={fetched} done={len(done)}/{len(shas)}", file=sys.stderr)


def crawl_ai_only_coauthored_commits(
    sess: requests.Session,
    outdir: Path,
    search_pages_per_query: int,
    search_sleep: float,
    verify_with_commit_detail: bool,
    skip_completed_queries: bool = True,
    start_page_by_agent: Optional[Dict[str, int]] = None,
) -> Dict[str, int]:
    outdir.mkdir(parents=True, exist_ok=True)
    scan_done_jsonl = outdir / "scan_done_ai_queries.jsonl"
    seen_query_markers = load_scanned_repos(scan_done_jsonl)
    global_seen_path = outdir / "ai_only_seen_commits.jsonl"
    seen_keys: Set[str] = set()
    if global_seen_path.exists():
        with global_seen_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    k = obj.get("key")
                    if k:
                        seen_keys.add(k)
                except json.JSONDecodeError:
                    continue

    query_specs: List[Tuple[str, str]] = []
    for agent, ident in AI_COAUTHOR_IDENTITIES.items():
        trailer = f'Co-authored-by: {ident["name"]} <{ident["email"]}>'
        q = f'"{trailer}" is:public'
        query_specs.append((agent, q))

    total_hits = 0
    total_matched_new = 0

    next_page_by_agent: Dict[str, int] = {}

    for agent, q in query_specs:
        marker = f"{agent}:{q}"
        if skip_completed_queries and marker in seen_query_markers:
            print(f"[ai-only] query already completed, skipping: {agent}", file=sys.stderr)
            continue

        start_page = max(1, int((start_page_by_agent or {}).get(agent, 1)))
        end_page = start_page + search_pages_per_query - 1
        print(
            f"[ai-only] searching query agent={agent} pages={start_page}..{end_page}",
            file=sys.stderr,
        )

        last_page = start_page - 1
        saw_empty_page = False

        for page in range(start_page, end_page + 1):
            last_page = page
            data = search_commits_page(sess, q=q, page=page, per_page=100)
            items = data.get("items") or []
            if not items:
                saw_empty_page = True
                break

            total_hits += len(items)
            for it in items:
                sha = (it.get("sha") or "").strip()
                repo_obj = it.get("repository") or {}
                repo_full = (repo_obj.get("full_name") or "").strip()
                if not sha or not repo_full or "/" not in repo_full:
                    continue
                key = f"{repo_full}@{sha}"
                if key in seen_keys:
                    continue

                owner, repo = repo_full.split("/", 1)
                msg = ((it.get("commit") or {}).get("message") or "").strip()
                if verify_with_commit_detail:
                    detail = get_commit_detail(sess, owner, repo, sha)
                    msg = (((detail.get("commit") or {}).get("message") or "")).strip()

                coinfo = ai_coauthor_info(msg)
                if not coinfo["ai_only"]:
                    continue

                repo_slug = slug(repo_full)
                repo_dir = outdir / "repos" / repo_slug
                repo_dir.mkdir(parents=True, exist_ok=True)
                commits_jsonl = repo_dir / "commits.jsonl"
                summary_path = repo_dir / "summary.json"

                row = {
                    "repo": repo_full,
                    "sha": sha,
                    "html_url": it.get("html_url"),
                    "commit_message": msg,
                    "agents": coinfo["agents"],
                    "confidence": "strict_coauthor_ai_only",
                    "signals": {
                        "coauthors": coinfo["coauthors"],
                        "source_query_agent": agent,
                        "source_query": q,
                    },
                }
                append_jsonl(commits_jsonl, row)
                append_jsonl(global_seen_path, {"key": key})
                seen_keys.add(key)
                total_matched_new += 1

                # Keep summary.json aligned with all matched commits in this repo.
                commits: List[Dict[str, Any]] = []
                with commits_jsonl.open("r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            commits.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                summary = {
                    "repo": repo_full,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "num_commits": len(commits),
                    "commits": commits,
                }
                summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

            if search_sleep > 0:
                time.sleep(search_sleep)

        # Progressive paging cursor:
        # - advance forward when current slice has results
        # - wrap to 1 once the query is exhausted (empty page encountered)
        next_page_by_agent[agent] = 1 if saw_empty_page else (last_page + 1)

        if skip_completed_queries:
            mark_repo_scanned(scan_done_jsonl, marker)
            seen_query_markers.add(marker)

    print(
        f"[ai-only] done total_hits={total_hits} matched_new={total_matched_new} unique_total={len(seen_keys)}",
        file=sys.stderr,
    )
    return next_page_by_agent


# ---------------- Repo list loading ----------------
def load_all_repos(repos_jsonl: Path) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    if not repos_jsonl.exists():
        return repos
    with repos_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                repos.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return repos


# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--mode",
        choices=["stars-scan", "ai-coauthor-only"],
        default="stars-scan",
        help="stars-scan: existing stars->repo->commit scan flow; ai-coauthor-only: global commit search for AI-only coauthor trailers",
    )
    ap.add_argument("--outdir", default=None, help="output directory (default depends on --mode)")
    ap.add_argument("--min-stars", type=int, default=100, help="discover repos with at least this many stars")
    ap.add_argument("--max-repos", type=int, default=10000, help="max repos to discover total")
    ap.add_argument("--search-sleep", type=float, default=2.2, help="sleep between Search API requests")
    ap.add_argument("--scan-pages-per-repo", type=int, default=50, help="first N pages of commits to scan (page size=100)")
    ap.add_argument("--fetch-diffs", action="store_true", help="fetch commit details (files + patch) for matched SHAs")
    ap.add_argument("--max-diffs-per-repo", type=int, default=200, help="limit diff fetches per repo per run")
    ap.add_argument("--discover-only", action="store_true")
    ap.add_argument("--scan-only", action="store_true")
    ap.add_argument("--force-rescan", action="store_true", help="ignore skip checks and rescan repos")
    ap.add_argument("--skip-if-scanned", action="store_true",
                    help="crash-resume mode: skip repos already recorded in scan_done.jsonl")
    ap.add_argument(
        "--ai-search-pages-per-query",
        type=int,
        default=10,
        help="ai-coauthor-only mode: max commit-search pages (100/page) per AI query",
    )
    ap.add_argument(
        "--ai-verify-with-commit-detail",
        dest="ai_verify_with_commit_detail",
        action="store_true",
        help="ai-coauthor-only mode: verify candidate commits with /repos/{owner}/{repo}/commits/{sha} for full message",
    )
    ap.add_argument(
        "--no-ai-verify-with-commit-detail",
        dest="ai_verify_with_commit_detail",
        action="store_false",
        help="ai-coauthor-only mode: skip per-commit detail fetch (faster, less strict)",
    )
    ap.add_argument(
        "--ai-continuous",
        action="store_true",
        help="ai-coauthor-only mode: run continuously and poll for new commits",
    )
    ap.add_argument(
        "--ai-poll-interval-seconds",
        type=float,
        default=120.0,
        help="ai-coauthor-only mode: sleep between continuous polling rounds",
    )
    ap.add_argument(
        "--ai-progressive-pages",
        action="store_true",
        help="ai-coauthor-only mode: in continuous mode, advance page windows each round (1..N, then N+1..2N, etc.)",
    )
    ap.add_argument(
        "--no-ai-progressive-pages",
        dest="ai_progressive_pages",
        action="store_false",
        help="ai-coauthor-only mode: in continuous mode, always rescan top pages each round",
    )
    ap.set_defaults(ai_progressive_pages=True)
    ap.set_defaults(ai_verify_with_commit_detail=True)
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[warn] GITHUB_TOKEN not set; you will hit low rate limits.", file=sys.stderr)

    default_outdir = "out_ai_coauthor_only" if args.mode == "ai-coauthor-only" else "out"
    outdir = Path(args.outdir or default_outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    sess = github_session(token)

    if args.mode == "ai-coauthor-only":
        if args.ai_continuous:
            ai_page_state_path = outdir / "ai_query_page_state.json"
            ai_page_state = load_json(ai_page_state_path, default={"next_page_by_agent": {}})
            round_idx = 0
            while True:
                round_idx += 1
                print(f"[ai-only] continuous round={round_idx} start", file=sys.stderr)
                try:
                    next_page_by_agent = crawl_ai_only_coauthored_commits(
                        sess=sess,
                        outdir=outdir,
                        search_pages_per_query=args.ai_search_pages_per_query,
                        search_sleep=args.search_sleep,
                        verify_with_commit_detail=args.ai_verify_with_commit_detail,
                        skip_completed_queries=False,
                        start_page_by_agent=(
                            (ai_page_state.get("next_page_by_agent") or {})
                            if args.ai_progressive_pages else {}
                        ),
                    )
                    if args.ai_progressive_pages:
                        ai_page_state["next_page_by_agent"] = next_page_by_agent
                        ai_page_state["last_round_at"] = to_iso_z(datetime.now(timezone.utc))
                        ai_page_state["last_round"] = round_idx
                        save_json(ai_page_state_path, ai_page_state)
                except Exception as e:
                    print(f"[ai-only] round={round_idx} error: {e}", file=sys.stderr)
                if args.ai_poll_interval_seconds > 0:
                    time.sleep(args.ai_poll_interval_seconds)
        else:
            crawl_ai_only_coauthored_commits(
                sess=sess,
                outdir=outdir,
                search_pages_per_query=args.ai_search_pages_per_query,
                search_sleep=args.search_sleep,
                verify_with_commit_detail=args.ai_verify_with_commit_detail,
                skip_completed_queries=True,
            )
        return

    scan_done_jsonl = outdir / "scan_done.jsonl"
    scan_state_path = outdir / "scan_state.json"
    scanned_repos_cache = load_scanned_repos(scan_done_jsonl)

    if not args.scan_only:
        discover_repos_stars(
            sess,
            outdir,
            min_stars=args.min_stars,
            max_repos=args.max_repos,
            search_sleep=args.search_sleep,
        )
        if args.discover_only:
            return

    repos = load_all_repos(outdir / "repos.jsonl")
    repos.sort(key=lambda r: int(r.get("stargazers_count") or 0), reverse=True)

    for r in repos:
        repo_full = r["full_name"]
        try:
            scan_repo_commits(
                sess,
                outdir,
                repo_full,
                max_pages=args.scan_pages_per_repo,
                scan_state_path=scan_state_path,
                scan_done_jsonl=scan_done_jsonl,
                scanned_repos_cache=scanned_repos_cache,
                skip_if_scanned=args.skip_if_scanned,
                force_rescan=args.force_rescan,
            )
            if args.fetch_diffs:
                fetch_repo_diffs(sess, outdir, repo_full, max_diffs_per_repo=args.max_diffs_per_repo)
        except Exception as e:
            print(f"[error] {repo_full}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()