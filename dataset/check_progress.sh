#!/bin/bash
# Check progress of the scale-out pipeline
# Usage: bash check_progress.sh

DATASET_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="$DATASET_DIR/scale_out.log"
TASKS_DIR="$DATASET_DIR/data/tasks"

echo "=== Scale-Out Pipeline Progress ==="
echo ""

# Check if still running
if pgrep -f "scale_out.py" > /dev/null; then
    echo "STATUS: RUNNING"
    PID=$(pgrep -f "scale_out.py")
    echo "PID: $PID"
else
    echo "STATUS: COMPLETED (or stopped)"
fi
echo ""

# Task counts
TOTAL_DIRS=$(find "$TASKS_DIR" -maxdepth 1 -type d | wc -l)
TOTAL_DIRS=$((TOTAL_DIRS - 1))  # subtract the tasks dir itself
echo "Total task directories: $TOTAL_DIRS"
echo ""

# Count by status in log
if [ -f "$LOG" ]; then
    echo "From log:"
    GENERATED=$(grep -c "Status: generated" "$LOG" || echo 0)
    PARTIAL=$(grep -c "Status: partial" "$LOG" || echo 0)
    ERRORS=$(grep -c "Status: error" "$LOG" || echo 0)
    echo "  Generated: $GENERATED"
    echo "  Partial:   $PARTIAL"
    echo "  Errors:    $ERRORS"
    echo ""

    # Latest task
    echo "Latest task being processed:"
    grep "\[INFO\] \[" "$LOG" | tail -1
    echo ""

    # Validation results (if any)
    VAL_PERFECT=$(grep -c "PERFECT:" "$LOG" || echo 0)
    VAL_PARTIAL=$(grep -c "PARTIAL:" "$LOG" || echo 0)
    VAL_NEEDS_FIX=$(grep -c "NEEDS_FIX:" "$LOG" || echo 0)
    if [ "$VAL_PERFECT" -gt 0 ] || [ "$VAL_PARTIAL" -gt 0 ] || [ "$VAL_NEEDS_FIX" -gt 0 ]; then
        echo "Validation results:"
        echo "  PERFECT:   $VAL_PERFECT"
        echo "  PARTIAL:   $VAL_PARTIAL"
        echo "  NEEDS_FIX: $VAL_NEEDS_FIX"
    fi
fi

# Results JSON
if [ -f "$DATASET_DIR/scale_out_results.json" ]; then
    echo ""
    echo "Results summary (from scale_out_results.json):"
    python3 -c "
import json
with open('$DATASET_DIR/scale_out_results.json') as f:
    data = json.load(f)
print(f'  Timestamp: {data.get(\"timestamp\", \"?\")}')
print(f'  Stats: {data.get(\"stats\", {})}')
print(f'  Total tasks: {data.get(\"total_tasks\", \"?\")}')
" 2>/dev/null
fi

echo ""
echo "=== Quick Commands ==="
echo "  tail -f $LOG                    # Watch live progress"
echo "  python evaluate_task.py --all   # Evaluate all tasks"
echo "  python organize_tasks.py        # Regenerate prompts/READMEs"
echo "  python scale_out.py --validate-only  # Validate all tasks"
