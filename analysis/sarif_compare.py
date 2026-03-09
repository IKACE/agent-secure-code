"""
Compare SARIF results before vs after an AI commit and attribute new findings
in AI-edited files to the AI-assisted commit.

Supports CodeQL security-severity: findings are enriched with numeric
security_severity and severity_level (critical/high/medium/low). Filter by
severity in downstream tools if needed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# CVSS score ranges for severity level labels (GitHub code scanning convention)
SEVERITY_LEVEL_BY_SCORE: List[Tuple[float, float, str]] = [
    (9.0, 10.0, "critical"),
    (7.0, 8.9, "high"),
    (4.0, 6.9, "medium"),
    (0.1, 3.9, "low"),
]


def _score_to_level(score: float) -> str:
    """Map numeric security-severity (CVSS-style) to level label."""
    for low, high, level in SEVERITY_LEVEL_BY_SCORE:
        if low <= score <= high:
            return level
    return "unknown"


def _rule_severity_map_from_sarif(sarif_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Build ruleId -> { "security_severity": float, "severity_level": str } from SARIF.
    Reads from run.tool.driver.rules and run.tool.extensions[].rules (CodeQL structure).
    """
    out: Dict[str, Dict[str, Any]] = {}
    for run in sarif_data.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        rules = driver.get("rules") or []
        for rule in rules:
            rule_id = rule.get("id") or ""
            if not rule_id:
                continue
            props = rule.get("properties") or {}
            raw = props.get("security-severity")
            if raw is None:
                continue
            try:
                score = float(raw)
            except (TypeError, ValueError):
                continue
            out[rule_id] = {
                "security_severity": score,
                "severity_level": _score_to_level(score),
            }
        for ext in driver.get("extensions") or []:
            for rule in ext.get("rules") or []:
                rule_id = rule.get("id") or ""
                if not rule_id or rule_id in out:
                    continue
                props = rule.get("properties") or {}
                raw = props.get("security-severity")
                if raw is None:
                    continue
                try:
                    score = float(raw)
                except (TypeError, ValueError):
                    continue
                out[rule_id] = {
                    "security_severity": score,
                    "severity_level": _score_to_level(score),
                }
    return out


def _normalize_path(uri: str, repo_root_name: str = "") -> str:
    """Convert SARIF file URI to repo-relative path (forward slashes)."""
    if not uri:
        return ""
    # file:///abs/path or file:///C:/path or relative path
    if uri.startswith("file:///"):
        path = uri[7:]  # strip file:///
        # On Windows, might be file:///C:/... -> C:/
        if len(path) >= 2 and path[1] == ":":
            path = path[2:].lstrip("/")
    else:
        path = uri
    # Normalize to forward slashes and strip leading slashes
    path = path.replace("\\", "/").lstrip("/")
    # Some SARIF uses full path; keep only the part after repo dir name if present
    if repo_root_name and repo_root_name in path:
        idx = path.find(repo_root_name)
        path = path[idx + len(repo_root_name) :].lstrip("/")
    return path


def _result_key(file_path: str, line: int, rule_id: str) -> Tuple[str, int, str]:
    """Canonical key for deduplication and set comparison."""
    return (file_path, line, rule_id or "")


def extract_findings(sarif_path: Path, repo_root_name: str = "") -> Set[Tuple[str, int, str]]:
    """
    Load a SARIF file and return set of (repo_relative_file, start_line, rule_id).
    """
    if not sarif_path.exists():
        return set()
    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()

    out: Set[Tuple[str, int, str]] = set()
    runs = data.get("runs") or []
    for run in runs:
        results = run.get("results") or []
        # Resolve artifact locations from run.artifacts if present
        artifacts = run.get("artifacts") or []
        uri_to_path: Dict[int, str] = {}  # index -> normalized path
        for i, art in enumerate(artifacts):
            loc = art.get("location") or {}
            uri = (loc.get("uri") or "").strip()
            uri_to_path[i] = _normalize_path(uri, repo_root_name)

        for res in results:
            rule_id = res.get("ruleId") or ""
            locs = res.get("locations") or []
            for loc in locs:
                phys = (loc.get("physicalLocation") or {}).get("artifactLocation") or {}
                uri = phys.get("uri") or ""
                artifact_index = phys.get("index")
                if artifact_index is not None and artifact_index in uri_to_path:
                    file_path = uri_to_path[artifact_index]
                else:
                    file_path = _normalize_path(uri, repo_root_name)
                region = (loc.get("physicalLocation") or {}).get("region") or {}
                line = int(region.get("startLine") or region.get("endLine") or 0)
                if file_path:
                    out.add(_result_key(file_path, line, rule_id))
            # Some results have a single location at top level
            if not locs:
                msg = res.get("message", {})
                if isinstance(msg, dict):
                    msg = msg.get("text") or ""
                out.add(("", 0, rule_id))
    return out


def ai_introduced_findings(
    after_sarif: Path,
    ai_edited_files: List[str],
    changed_lines: Dict[str, Set[int]],
    repo_root_name: str = "",
) -> List[Dict[str, Any]]:
    """
    Find alerts that appear in after_sarif and lie on lines that were changed
    by the AI-assisted commit in AI-edited files.

    The `changed_lines` map should contain, for each repo-relative filename,
    the set of line numbers (in the after revision) that were added/modified
    by the commit. Files that were edited but have no entry in `changed_lines`
    are treated as having unknown line ranges and will not be filtered by line.

    Each finding is enriched with security_severity (float, from CodeQL rule
    metadata) and severity_level ("critical"|"high"|"medium"|"low") when the
    rule declares @security-severity. Filter by severity downstream if needed.
    """
    # Normalize AI-edited file paths to forward slashes for matching
    ai_files_set: Set[str] = set()
    for f in ai_edited_files:
        p = f.replace("\\", "/").strip("/")
        ai_files_set.add(p)
        # Also allow match when SARIF path has leading segment (e.g. repo name)
        ai_files_set.add(f.replace("\\", "/"))

    # Normalize changed_lines keys similarly for robust matching
    normalized_changed: Dict[str, Set[int]] = {}
    for path, lines in changed_lines.items():
        norm = path.replace("\\", "/").strip("/")
        normalized_changed[norm] = set(lines)

    # Load after SARIF and build rule severity map from it
    after_results_by_key: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
    rule_severity: Dict[str, Dict[str, Any]] = {}
    if after_sarif.exists():
        try:
            data = json.loads(after_sarif.read_text(encoding="utf-8"))
            rule_severity = _rule_severity_map_from_sarif(data)
            for run in data.get("runs") or []:
                artifacts = run.get("artifacts") or []
                uri_to_path = {}
                for i, art in enumerate(artifacts):
                    uri = ((art.get("location") or {}).get("uri") or "").strip()
                    uri_to_path[i] = _normalize_path(uri, repo_root_name)
                for res in run.get("results") or []:
                    rule_id = res.get("ruleId") or ""
                    for loc in res.get("locations") or []:
                        phys = (loc.get("physicalLocation") or {}).get("artifactLocation") or {}
                        artifact_index = phys.get("index")
                        uri = phys.get("uri") or ""
                        if artifact_index is not None and artifact_index in uri_to_path:
                            file_path = uri_to_path[artifact_index]
                        else:
                            file_path = _normalize_path(uri, repo_root_name)
                        region = (loc.get("physicalLocation") or {}).get("region") or {}
                        line = int(region.get("startLine") or region.get("endLine") or 0)
                        key = _result_key(file_path, line, rule_id)
                        msg = res.get("message") or {}
                        if isinstance(msg, dict):
                            msg = msg.get("text") or str(msg)
                        rec: Dict[str, Any] = {
                            "file": file_path,
                            "line": line,
                            "ruleId": rule_id,
                            "message": msg,
                        }
                        if rule_id in rule_severity:
                            rec["security_severity"] = rule_severity[rule_id]["security_severity"]
                            rec["severity_level"] = rule_severity[rule_id]["severity_level"]
                        after_results_by_key[key] = rec
        except (json.JSONDecodeError, OSError):
            pass

    introduced: List[Dict[str, Any]] = []
    for key, rec in after_results_by_key.items():
        file_path = rec.get("file") or ""
        line = int(rec.get("line") or 0)
        if not file_path or line <= 0:
            continue

        # Match if this finding's file is one of the AI-edited files (repo-relative)
        norm_path = file_path.replace("\\", "/").strip("/")
        in_ai_file = norm_path in ai_files_set or any(
            norm_path == af or norm_path.endswith("/" + af.strip("/"))
            for af in ai_files_set
        )
        if not in_ai_file:
            continue

        # If we have per-file changed line info, require the line to be in that set.
        if norm_path in normalized_changed:
            if line not in normalized_changed[norm_path]:
                continue

        introduced.append(rec)
    return introduced
