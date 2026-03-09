# Patch analysis: AI commit vulnerability attribution

This module uses **CodeQL** (and optional other static analyzers) to compare the repo **before** vs **after** an AI-assisted commit. Findings that appear **after** the commit, in **files touched by the AI commit**, and that were **not** present **before** are attributed as **AI-introduced** vulnerabilities.

## Idea

1. For each collected AI commit (from `github_study` crawl output), we have:
   - `sha`, `repo`, and `files[]` (paths changed in that commit).
2. Run static analysis (CodeQL) on the repo at **parent commit** → `before.sarif`.
3. Run static analysis on the repo at **AI commit** → `after.sarif`.
4. **Compare**: any result in `after.sarif` that:
   - is in a file listed in `files[]`, and  
   - has no matching result (same file, line, rule) in `before.sarif`  
   → count as **AI-introduced**.

So: *“If the vulnerability is in a file the AI commit edited and wasn’t there before the AI commit, it is attributed to the AI.”*

## Requirements

- **CodeQL CLI** on `PATH` (e.g. from [CodeQL bundle](https://github.com/github/codeql-action/releases)).
- **git** (clone and checkout).
- Crawl output layout: `{crawl_outdir}/repos/{owner__repo}/diffs/{sha}.json` with `repo`, `sha`, `files[].filename`.

**Build mode (language-dependent):** CodeQL `database create` sets build mode from the languages inferred from the commit’s changed files: **`none`** for JavaScript/TypeScript, Python, Ruby, C#, Java (no build); **`autobuild`** when any of C/C++, Go, or Swift is present. When the commit touches files in **more than one language**, the script uses **`--db-cluster`** so CodeQL creates one database per language. For **analyze**, the script detects the cluster (e.g. `db_before/javascript`, `db_before/python`), runs CodeQL analyze on each language DB, then **merges** the SARIFs into one `before.sarif` / `after.sarif` (some CodeQL CLI versions do not accept the cluster path directly).

## Usage

### Full pipeline (clone + CodeQL before/after + compare)

From `github_study` (or with `patch_analysis` on `PYTHONPATH`):

```bash
cd agent-blockchain-security/github_study
python patch_analysis/run_codeql_diff.py --crawl-outdir output [options]
```

Options:

- `--crawl-outdir PATH` — Crawl output dir (default: `output`).
- `--workspace PATH` — Where to clone repos. Default: `PATCH_ANALYSIS_WORKSPACE` env (if set) else `patch_analysis/workspace`. Use a path on a large disk (e.g. `/mnt/storage/patch_analysis_workspace`) to avoid filling the root filesystem.
- `--report-dir PATH` — Where to write reports and CodeQL DBs (SARIFs, `codeql_report.json`). Default: `PATCH_ANALYSIS_REPORT_DIR` env (if set) else `patch_analysis/output`. CodeQL databases under each commit dir can be large; point to a big disk if needed.
- `--codeql CMD` — CodeQL binary (default: `codeql`).
- `--codeql-suites-dir PATH` — Path to `codeql-suites` (optional; auto-detected from `codeql` binary when possible).
- `--repo owner/name` — Restrict to one repo.
- `--sha SHA` — Restrict to one commit.
- `--list-only` — Only list `repo`/`sha` pairs and exit.
- `--no-skip-done` — Re-run even when `codeql_report.json` already exists (default: skip already-analyzed commits).
- `--analyze-timeout N` — CodeQL analyze timeout in seconds (default 1800). Increase for very large repos if you see analyze timeouts.
- `--jobs N` / `-j N` — Run up to N commits in parallel (default 1). Commits from the same repo are serialized (one at a time per clone); parallelism is across repos. The **todo list is reordered round-robin by repo** so the first N tasks are from N different repos when possible, keeping all workers busy. With `-j > 1` you get **progress logging**: `Running N commits with -j J workers.`, `[start] repo sha`, and `[done]/[skip] ... (M/N)`.

Example (run all):

```bash
python github_study/patch_analysis/run_codeql_diff.py --crawl-outdir github_study/output --codeql /path/to/codeql
```

Example (use a large disk for clones and reports to save space on `/`):

```bash
export PATCH_ANALYSIS_WORKSPACE=/mnt/storage/patch_analysis_workspace
export PATCH_ANALYSIS_REPORT_DIR=/mnt/storage/patch_analysis_output
python patch_analysis/run_codeql_diff.py --crawl-outdir github_study/output -j 8
```

Or pass paths explicitly: `--workspace /mnt/storage/patch_analysis_workspace --report-dir /mnt/storage/patch_analysis_output`.


Example (one commit):

```bash
python patch_analysis/run_codeql_diff.py --crawl-outdir output --repo infiniflow/ragflow --sha 395ce16b3ca930a2ccd88621cbd33546666bc323 --codeql /home/yilegu/agent-blockchain-security/codeql/codeql/codeql
```

Reports are written under `patch_analysis/output/{owner__repo}/{sha}/`:

- `before.sarif`, `after.sarif`
- `codeql_report.json`: `ai_edited_files`, `ai_introduced_findings`, `num_ai_introduced`

When scanning many commits, already-analyzed ones (with existing `codeql_report.json`) are skipped. On error for a commit, the script continues to the next and writes:

- `{sha}/error.json` — error type, `repo`, `sha`, and timestamp.
- `output/errors.jsonl` — one JSON object per line for every failed commit in the run (easy to grep or re-run).

### Compare only (existing SARIF files)

If you already have `before.sarif` and `after.sarif` (e.g. from a manual CodeQL run):

```bash
python patch_analysis/compare_sarif.py \
  --diff-json output/repos/infiniflow__ragflow/diffs/395ce16b3ca930a2ccd88621cbd33546666bc323.json \
  --before path/to/before.sarif \
  --after path/to/after.sarif \
  --output report.json
```

### Re-run attribution with severity (no CodeQL rerun)

If you already have `before.sarif` and `after.sarif` for many commits (e.g. from a previous full run), you **do not** need to rerun CodeQL. The SARIF files already contain rule metadata (including `security-severity`). Re-run only the **attribution** step to regenerate `codeql_report.json` with severity-enriched findings:

```bash
cd agent-blockchain-security/github_study
python patch_analysis/rerun_line_level_attribution.py \
  --report-root /path/to/report/dir \
  --crawl-outdir output
```

- `--report-root` — Directory containing `{owner__repo}/{sha}/before.sarif` and `after.sarif` (default: `PATCH_ANALYSIS_REPORT_DIR` or `patch_analysis/output`).
- `--crawl-outdir` — Crawl output with `repos/{owner__repo}/diffs/{sha}.json` (default: `output`).
- `--repo owner/name` — Restrict to one repository.

This overwrites `codeql_report.json` in each `{sha}/` with updated `ai_introduced_findings` that include `security_severity` and `severity_level`. Filter by severity in your own scripts or tools if needed.

## Output format

`codeql_report.json` (and `compare_sarif.py --output`) looks like:

```json
{
  "repo": "infiniflow/ragflow",
  "sha": "395ce16b...",
  "parent_sha": "...",
  "html_url": "https://github.com/...",
  "ai_edited_files": ["web/src/pages/.../edit-mcp-dialog.tsx", ...],
  "ai_introduced_findings": [
    {
      "file": "web/src/pages/.../edit-mcp-dialog.tsx",
      "line": 89,
      "ruleId": "js/...",
      "message": "...",
      "security_severity": 7.5,
      "severity_level": "high"
    }
  ],
  "num_ai_introduced": 1
}
```

`security_severity` (numeric CVSS-style score) and `severity_level` (`"critical"` | `"high"` | `"medium"` | `"low"`) are read from CodeQL rule metadata in the SARIF; they are present only for rules that declare `@security-severity`.

## Files

- `sarif_compare.py` — SARIF loading, path normalization, before/after set diff, attribution to AI-edited files; enriches findings with `security_severity` / `severity_level` from CodeQL rule metadata.
- `run_codeql_diff.py` — Clone, checkout parent/AI commit, CodeQL create + analyze, then compare and write report.
- `compare_sarif.py` — Compare two SARIF files with a diff JSON and write report (no CodeQL run).
- `rerun_line_level_attribution.py` — Recompute `codeql_report.json` from existing before/after SARIF and diff JSON (no CodeQL rerun).
- `README.md` — This file.
