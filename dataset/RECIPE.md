# Evaluation Recipe

Unified guide for evaluating implementations against the secure code generation dataset.

## Quick Start

```bash
# Evaluate all tasks with default insecure standalones:
python evaluate_task.py --all

# Compare insecure vs secure variants:
python evaluate_task.py --all --compare

# Evaluate a single task with a custom implementation:
python evaluate_task.py data/tasks/TASK_DIR/ path/to/my_impl.js

# JSON output for programmatic use:
python evaluate_task.py --all --json > results.json
```

## Per-Task Manual Evaluation

For any task directory under `data/tasks/`, follow these steps:

### Step 1: Understand the Task

```bash
cat data/tasks/<TASK_DIR>/task.json | python -m json.tool
cat data/tasks/<TASK_DIR>/README.md
```

Key fields in `task.json`:
- `vuln_function_name`: The function to implement
- `cwe`: The vulnerability type (e.g., CWE-78)
- `vuln_type`: Human-readable vulnerability description
- `function_summary`: What the function should do

### Step 2: Implement the Function

Create your implementation file (e.g., `my_impl.js` or `my_impl.py`). It must:
- Export the function named in `vuln_function_name`
- Supported export styles: `module.exports = func`, `module.exports = { func }`, or `module.exports.default = func`
- For Python: define the function at module level

### Step 3: Run Correctness Tests

```bash
# JavaScript:
node data/tasks/<TASK_DIR>/tests/test_correctness.js path/to/my_impl.js

# Python:
python -m pytest data/tasks/<TASK_DIR>/tests/test_correctness.py path/to/my_impl.py -v
```

Expected: All tests PASS. These verify the function works correctly for normal inputs.

### Step 4: Run Security Exploit Test

```bash
# JavaScript:
node data/tasks/<TASK_DIR>/tests/test_security.js path/to/my_impl.js

# Python:
python data/tasks/<TASK_DIR>/tests/test_security.py path/to/my_impl.py
```

Expected output:
- `VULNERABLE` (exit 1): The implementation has the vulnerability
- `SAFE` (exit 0): The implementation is secure against the tested exploit

### Step 5: Run Pattern-Based Vulnerability Check

```bash
python vuln_check.py --task-dir data/tasks/<TASK_DIR>/ --code-file path/to/my_impl.js
```

Returns JSON with `"vulnerable": true/false` based on regex pattern matching.

### Step 6 (Optional): CodeQL Integration

For Level 2 evaluation, integrate the implementation into the original repo and run CodeQL:

```bash
# 1. Clone the original repo at the vulnerable commit
git clone <repo_url> && cd <repo> && git checkout <sha>

# 2. Replace the vulnerable file with your implementation
# (Requires splicing into full file context)

# 3. Create CodeQL database and analyze
codeql database create mydb --language=javascript
codeql database analyze mydb codeql/javascript-queries --format=sarif-latest --output=results.sarif

# 4. Check for alerts matching the CWE
python -c "import json; r=json.load(open('results.sarif')); print(len(r['runs'][0]['results']))"
```

## Evaluation Dimensions

| Check | What It Measures | Speed | Accuracy |
|-------|-----------------|-------|----------|
| **Correctness** | Does the function work? | ~1s | High |
| **Security Exploit** | Can the vuln be exploited? | ~1s | High (for known patterns) |
| **Pattern Match** | Regex-based vuln detection | ~10ms | Medium (fragile to refactoring) |
| **CodeQL** | Static analysis | ~minutes | High (gold standard) |

For RL reward signals, combine: correctness (gate) + exploit test (primary) + pattern match (fast signal).

## How Tests Work

### Correctness Tests
- Test functional behavior with normal inputs
- Agnostic to security approach (work for both insecure and secure variants)
- Do NOT test vulnerability-specific behavior

### Security Exploit Tests
- Simulate real attack payloads without causing actual damage
- Mock dangerous sinks (execSync, fs.writeFileSync, fetch, etc.)
- Inject payloads (path traversal, command injection, XSS, SQL injection)
- Check if payload reaches the dangerous sink unsanitized
- Exit 1 = VULNERABLE, Exit 0 = SAFE

### Pattern Matching (vuln_check.py)
- Regex-based, NOT derived from CodeQL queries
- Hand-tuned for the 10 current tasks
- Fast but fragile to code style variations
- Best used as a quick signal, not ground truth

## Adding New Tasks

To extend the dataset with new tasks:

1. Create task directory under `data/tasks/` with naming convention:
   `{owner}__{repo}__{sha_prefix}__{vuln_type}__{file_path}`

2. Required files:
   - `task.json` - Task metadata (see existing tasks for schema)
   - `standalone.js` or `standalone.py` - Insecure implementation
   - `standalone_secure.js` or `standalone_secure.py` - Secure implementation
   - `tests/test_correctness.js` or `.py` - Correctness tests (parameterized)
   - `tests/test_security.js` or `.py` - Security exploit test (parameterized)
   - `README.md` - Task description

3. Test file requirements:
   - Accept implementation path as CLI argument (argv[2] for JS, argv[1] for Python)
   - Default to `../standalone.js` or `../standalone.py` if no argument
   - Handle flexible exports (function vs object with named export)
   - Correctness tests must pass for both insecure and secure variants
   - Security tests must return VULNERABLE for insecure, SAFE for secure

4. Add CWE patterns to `vuln_check.py` if the CWE is new

5. Verify with:
   ```bash
   python evaluate_task.py data/tasks/<NEW_TASK>/ standalone.js
   python evaluate_task.py data/tasks/<NEW_TASK>/ standalone_secure.js
   ```

## Current Coverage

| CWE | Count | Vulnerability Type |
|-----|-------|--------------------|
| CWE-78 | 2 | Command Injection |
| CWE-79 | 3 | Cross-Site Scripting (reflected, DOM, stored) |
| CWE-22 | 1 | Path Traversal |
| CWE-73 | 1 | File Path Injection |
| CWE-89 | 1 | SQL Injection |
| CWE-918 | 2 | Server-Side Request Forgery |
