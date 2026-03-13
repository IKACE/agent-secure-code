# Lessons Learned: Building Secure Code Generation Tasks

This document captures all mistakes made and lessons learned during the manual creation
of the first 10 tasks. These lessons are codified into the automated `scale_out.py`
pipeline to prevent recurrence at scale.

## 1. Prompt Quality

### Problem: Missing Data Provenance
The function description alone is insufficient for security-aware code generation.
For example, `storeCredentials(tokens, logErr)` says "saves OAuth tokens" but doesn't
say the tokens come from an **external network response**. Without this context,
a model has no reason to treat the input as untrusted.

**Fix:** Every task must include a `caller_context` field describing where function
inputs originate (HTTP request, external API, database, user form, etc.). This is
extracted from the CodeQL data flow message.

### Problem: Vulnerability Keywords Leaking into Prompts
Setup code contained comments like `// CWE-78`, `// Vulnerable function`,
`// SSRF vulnerability`. This gives away the answer.

**Fix:** `sanitize_for_prompt()` strips lines containing vulnerability keywords from
comments and docstrings. Keywords list: `vulnerab`, `cwe-`, `exploit`, `injection`,
`xss`, `ssrf`, `traversal`, `insecure`, `unsafe`, `malicious`, etc.

### Problem: Function Name Mismatch
task.json `vuln_function_name: "GET"` but the standalone exports `handleRequest`.
Prompt showed wrong function name.

**Fix:** Resolve actual function name by scanning `module.exports = X` or
`def X(` in the standalone file, not just task.json.

## 2. Test Infrastructure

### Problem: Hardcoded Import Paths
Tests used `require('../standalone')` or `from standalone import X`, ignoring the
`process.argv[2]` / `sys.argv[1]` parameter. When testing secure variants, they
silently tested the insecure variant instead.

**Fix:** All tests MUST use parameterized loading:
- JS: `process.argv[2] ? path.resolve(process.argv[2]) : path.join(__dirname, '..', 'standalone.js')`
- Python: `sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'standalone.py')`

### Problem: Inflexible Export Handling
`const func = require(implPath)` fails when secure variant exports `{ funcName }`
instead of the bare function.

**Fix:** Always use flexible export resolution:
```js
const _mod = require(implPath);
const func = typeof _mod === 'function' ? _mod : _mod.funcName || _mod.default;
```

### Problem: Correctness Tests Asserting Vulnerability-Specific Behavior
Tests like `assert(result.includes('<script>'))` ("should be unescaped") fail on
secure variants that properly escape HTML.

**Fix:** Correctness tests must only verify **functional** behavior for normal inputs.
Never assert that dangerous patterns are present. Test with inputs like `O'Brien & Sons`
that need encoding but aren't attack payloads.

### Problem: Security Tests Not Triggering on Valid Code Path
The Alvis1337 file write test injected username `../../../tmp/evil`, but this username
didn't exist in the mock database. The function returned `{success: false}` before
reaching the vulnerable write operation.

**Fix:** Security tests must ensure the exploit payload reaches the vulnerable sink.
If the function checks a database, inject the malicious data INTO the database first.

### Problem: Mocking Wrong APIs for Secure Variants
Insecure variant uses `execSync` (shell command), secure variant uses `spawnSync`
(no shell). If the test only mocks `execSync`, the secure variant's calls go
unmocked and may error.

**Fix:** Mock ALL relevant APIs for both variants. For CWE-78:
```js
child_process.execSync = (cmd) => { capturedCommands.push(cmd); };
child_process.spawnSync = (bin, args) => { /* record but don't flag as vulnerable */ };
```

### Problem: Python Test Self-Loading
pytest's argv contains `tests/test_correctness.py` which matched the `.py` file
scan pattern, causing infinite recursion.

**Fix:** Filter test files from implementation path resolution:
```python
'test_' not in os.path.basename(arg)
```

### Problem: UUID Validation in Secure Variants
Test used `"valid_release_group_id"` as a MusicBrainz ID. Secure variant validates
UUID format and rejects it.

**Fix:** Use realistic test data that passes validation:
`"a1b2c3d4-e5f6-7890-abcd-ef1234567890"` instead of descriptive strings.

## 3. Standalone Implementations

### Problem: External Dependencies (express, etc.)
Secure variant used `require('express')` which isn't installed.

**Fix:** All standalone implementations must use ONLY Node.js built-in modules
(`http`, `fs`, `path`, `child_process`, `crypto`, `url`, `querystring`) or
Python stdlib. No third-party dependencies except what's in the setup code.

### Problem: Standalone Missing Required Exports
Security tests need to inject data into internal state (e.g., mock database).
If the standalone doesn't export these internals, tests can't set up exploits.

**Fix:** Export internal state needed for testing:
```js
module.exports = mainFunction;
module.exports.mockDatabase = mockDatabase; // For test injection
```

## 4. Evaluation Pipeline

### Problem: vuln_check.py Flag Format
Originally called with positional args, but it uses `--task-dir` / `--code-file` flags.

**Fix:** Always use flag-based invocation and parse JSON output.

### Problem: evaluate.sh with `set -e`
`set -e` causes the script to exit on first test failure, skipping subsequent checks.

**Fix:** Capture exit codes in variables (`CORRECTNESS=$?`) and continue.
The `set -e` is still useful for setup commands.

## 5. Organization

### Problem: Outdated README References
README referenced deleted files (`test_standalone.js`, `run.sh`) and wrong
file names (`prompt.txt` instead of `prompt.md`).

**Fix:** Generate README programmatically via `organize_tasks.py` so it always
reflects the current structure.

### Problem: Ad-hoc File Generation
Hand-creating files leads to inconsistencies. Different tasks had different
prompt formats, test structures, and evaluation scripts.

**Fix:** All generated files come from `organize_tasks.py`. Manual edits should
only be to `task.json`, standalone implementations, and test files.

## 6. Scale-Out Implications

These lessons inform the automated pipeline (`scale_out.py`):

1. **LLM prompt for standalone generation** must specify:
   - Use only stdlib modules
   - Export the function AND any internal state needed for testing
   - Include realistic mock data
   - No vulnerability keywords in comments

2. **LLM prompt for test generation** must specify:
   - Parameterized loading (argv-based)
   - Flexible export handling
   - Correctness tests: normal inputs only, no vulnerability assertions
   - Security tests: mock the dangerous sink, inject payload, check if it reaches sink
   - Must work for BOTH insecure and secure variants

3. **LLM prompt for caller_context** must specify:
   - Describe where inputs come from (HTTP request, external API, etc.)
   - Do NOT mention the vulnerability type
   - Do NOT use words like "vulnerable", "insecure", "attack"

4. **Validation** after generation:
   - Run correctness tests on insecure variant → must PASS
   - Run correctness tests on secure variant → must PASS
   - Run security tests on insecure variant → must return VULNERABLE
   - Run security tests on secure variant → must return SAFE
   - Any mismatch → flag for review
