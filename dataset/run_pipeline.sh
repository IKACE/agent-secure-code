#!/usr/bin/env bash
#
# End-to-end pipeline for the function-level security evaluation dataset.
#
# Stages:
#   1. generate_tasks.py    — Extract tasks from vulnerability data
#   2. generate_prompts.py  — Generate function summaries + prompts via LLM
#   3. setup_task_dirs.py   — Create per-task folder structure
#   4. generate_tests.py    — Generate unit tests via LLM
#   5. (manual)             — Run a model on the prompts
#   6. evaluate_task.py     — Evaluate generated code
#
# Usage:
#   ./run_pipeline.sh                  # Run stages 1-4 (generate dataset)
#   ./run_pipeline.sh --limit 10       # Generate 10 tasks
#   ./run_pipeline.sh --stage 3        # Start from stage 3
#   ./run_pipeline.sh --eval MODEL_DIR # Run evaluation (stage 6)

set -euo pipefail
cd "$(dirname "$0")"

LIMIT="${LIMIT:-10}"
STAGE="${STAGE:-1}"
EVAL_DIR=""

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --limit)   LIMIT="$2"; shift 2 ;;
        --stage)   STAGE="$2"; shift 2 ;;
        --eval)    EVAL_DIR="$2"; shift 2 ;;
        *)         echo "Unknown arg: $1"; exit 1 ;;
    esac
done

TASKS_JSONL="data/tasks_function_level.jsonl"
TASKS_DIR="data/tasks"

echo "=== Function-Level Security Evaluation Pipeline ==="
echo "Limit: $LIMIT  Starting stage: $STAGE"
echo ""

# --- Stage 1: Generate tasks ---
if [[ $STAGE -le 1 ]]; then
    echo "--- Stage 1: Generate tasks ---"
    python3 generate_tasks.py --limit "$LIMIT" --output "$TASKS_JSONL"
    echo ""
fi

# --- Stage 2: Generate prompts ---
if [[ $STAGE -le 2 ]]; then
    echo "--- Stage 2: Generate prompts (LLM calls) ---"
    python3 generate_prompts.py --tasks "$TASKS_JSONL" --force
    # Rebuild tier1 with real summaries
    python3 generate_prompts.py --tasks "$TASKS_JSONL" --tier1-only --force
    echo ""
fi

# --- Stage 3: Set up task directories ---
if [[ $STAGE -le 3 ]]; then
    echo "--- Stage 3: Set up task directories ---"
    python3 setup_task_dirs.py --tasks "$TASKS_JSONL" --output "$TASKS_DIR" --clean
    echo ""
fi

# --- Stage 4: Generate unit tests ---
if [[ $STAGE -le 4 ]]; then
    echo "--- Stage 4: Generate unit tests (LLM calls) ---"
    python3 generate_tests.py --tasks-dir "$TASKS_DIR" --tasks-jsonl "$TASKS_JSONL" --force
    echo ""
fi

# --- Stage 5: Run model (manual) ---
if [[ $STAGE -le 5 ]] && [[ -z "$EVAL_DIR" ]]; then
    echo "--- Stage 5: Run your model ---"
    echo "Feed the prompts to your model and save outputs to:"
    echo "  results/MODEL_NAME/TASK_ID/generated_code.txt"
    echo ""
    echo "Example using the tier1 prompts:"
    echo "  for d in $TASKS_DIR/*/; do"
    echo "    task_id=\$(basename \$d)"
    echo "    prompt=\$d/prompt_tier1.txt"
    echo "    # your_model < \$prompt > results/MODEL_NAME/\$task_id/generated_code.txt"
    echo "  done"
    echo ""
fi

# --- Stage 6: Evaluate ---
if [[ -n "$EVAL_DIR" ]]; then
    echo "--- Stage 6: Evaluate model outputs ---"
    python3 evaluate_task.py \
        --tasks-dir "$TASKS_DIR" \
        --results-dir "$EVAL_DIR"
    echo ""
fi

echo "=== Pipeline complete ==="
