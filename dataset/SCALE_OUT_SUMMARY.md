# Scale-Out Summary

## What's Running

The `scale_out.py` pipeline is running in background, processing all VulnHalla true
positive findings (JS + Python) into complete task directories.

**Started:** 2026-03-13 ~09:39 UTC
**Estimated completion:** ~12:00 UTC (2.5-3 hours)

### How to Check Progress

```bash
cd /home/yilegu/agent-secure-code-gen/agent-secure-code-repo/dataset

# Quick status
bash check_progress.sh

# Watch live
tail -f scale_out.log

# Count tasks
ls data/tasks/ | wc -l
```

## Data Sources

| Source | Records | Scope |
|--------|---------|-------|
| `tasks_function_level.jsonl` | 10 | Original hand-verified tasks (already done) |
| `tasks.jsonl` | 50 | Commit-level entries |
| VulnHalla summary | 660 | All JS+Python true positives from 147 repos |

After deduplication and priority filtering: ~390 tasks being processed.

## Pipeline: What Happens Per Task

For each vulnerability finding, `scale_out.py`:

1. **Reads** the vulnerable source file from `/mnt/storage/yilegu/patch_analysis/ai_commit_dbs/workspace/`
2. **Extracts** the vulnerable function using regex-based extraction (handles top-level functions, class methods, arrow functions)
3. **LLM generates** (6 calls to Azure OpenAI gpt-4o):
   - `function_summary` — what the function does
   - `caller_context` — where inputs come from (without revealing the vulnerability)
   - `standalone.{ext}` — insecure reference implementation using only stdlib
   - `standalone_secure.{ext}` — secure version that fixes the vulnerability
   - `tests/test_correctness.{ext}` — functional tests (parameterized, variant-agnostic)
   - `tests/test_security.{ext}` — exploit simulation test (mock sink, inject payload)
4. **Creates** `task.json` with all metadata
5. Runs `organize_tasks.py` to generate:
   - `prompt.md` — RL prompt with calling context
   - `README.md` — human-readable task description
   - `evaluate.sh` — unified evaluation script
6. **Validates** by running tests on both variants

## Expected Quality

The auto-generated tasks follow all lessons from `lessons_learned.md`:
- Prompts include `caller_context` (data provenance)
- Vulnerability keywords sanitized from prompts
- Tests use parameterized loading (argv-based)
- Tests use flexible export handling
- Correctness tests only verify functional behavior
- Security tests mock dangerous sinks

**However**, LLM-generated code is imperfect. Expect:
- ~60-70% of tasks to have working correctness tests
- ~50-60% to have correct security exploit detection
- ~30-40% "PERFECT" (both variants pass both test types correctly)
- Remaining tasks need manual review/fixing

## After the Run

### Quick Evaluation
```bash
# Validate all tasks
python scale_out.py --validate-only

# Full evaluation with the original evaluator
python evaluate_task.py --all --compare
```

### Scale to Non-Priority Types
```bash
# Process all remaining finding types (not just priority CWEs)
python scale_out.py --source vulnhalla --skip-existing
```

### Continuous Pipeline (Future)
The pipeline is designed for continuous use:
```bash
# 1. New VulnHalla findings arrive (update the summary JSON)
# 2. Run scale_out.py with --skip-existing
python scale_out.py --skip-existing --validate

# 3. Review validation results
python scale_out.py --validate-only

# 4. Fix failing tasks
# (manual or re-generate with different LLM params)
```

## CWE Coverage

### Original 10 Tasks (100% validated)
CWE-78 (2), CWE-79 (3), CWE-22 (1), CWE-73 (1), CWE-89 (1), CWE-918 (2)

### Scale-Out Priority Types (~390 tasks)
CWE-78, CWE-79, CWE-89, CWE-918, CWE-22, CWE-73, CWE-117, CWE-330, CWE-20, CWE-312, CWE-532, CWE-377

### Full VulnHalla (~660 findings)
Adds: CWE-367, CWE-1333, CWE-200, CWE-134, CWE-770, CWE-807, CWE-327, CWE-1321, CWE-295, CWE-400, CWE-601, CWE-916, CWE-489, and more

## File Structure

```
dataset/
  scale_out.py              # Main pipeline script
  scale_out.log             # Structured log (persistent)
  scale_out_results.json    # Machine-readable results
  scale_out_stdout.log      # Full stdout/stderr
  check_progress.sh         # Progress monitoring script
  organize_tasks.py         # Prompt/README/evaluate.sh generator
  evaluate_task.py          # Unified task evaluator
  lessons_learned.md        # All mistakes and fixes documented
  SCALE_OUT_SUMMARY.md      # This file
  data/
    tasks/                  # All task directories
      {task_id}/
        task.json
        prompt.md
        README.md
        evaluate.sh
        standalone.{ext}
        standalone_secure.{ext}
        original_function.{ext}
        tests/
          test_correctness.{ext}
          test_security.{ext}
```
