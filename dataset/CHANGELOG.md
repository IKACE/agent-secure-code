# Evaluation Infrastructure Changelog

## Audit and Cleanup Pass (March 13 2026)

Post-rewrite audit found and fixed several issues in test files:

### Bugs found
- **DrighnaTechnology test_correctness.js**: `setupMock()` hardcoded `require('../standalone')`,
  ignoring the CLI argument entirely. When called with `standalone_secure.js`, it silently
  tested the insecure variant instead. **Complete rewrite** — now parameterized with
  `loadImpl()` pattern, mocks both `child_process.exec` and `child_process.execFile`.
- **Smart-AI-Memory test_correctness.js**: Missing flexible export handling
  (`const renderTagPage = require(implPath)` instead of `typeof _mod` pattern). Fixed.

### Cleanup
- Removed all 10 old `test_standalone.js/py` files (superseded by `test_correctness.*`)
- Removed `__pycache__` directories
- Each task now has exactly: `test_correctness.js/py` + `test_security.js/py`

### Audit checklist (all 10 tasks verified)
- [x] `test_correctness` accepts impl path via `process.argv[2]` / `sys.argv`
- [x] `test_correctness` uses flexible export: `typeof _mod === 'function' ? _mod : _mod.funcName || _mod.default`
- [x] `test_correctness` only tests functional behavior (no vulnerability-specific assertions)
- [x] `test_correctness` passes for BOTH insecure and secure variants
- [x] `test_security` accepts impl path via CLI argument
- [x] `test_security` uses flexible export handling
- [x] `test_security` returns VULNERABLE for insecure, SAFE for secure
- [x] No hardcoded `require('../standalone')` in any test_correctness or test_security
- [x] No old test_standalone files remain

---

## Rewrite Summary (March 2026)

The evaluation infrastructure was redesigned to support parameterized, scalable testing
across any implementation file - not just `standalone.js`. This document records all
significant changes.

---

## Architectural Changes

### Before (v0)
- Tests were hardcoded to `require('../standalone.js')`
- Correctness tests asserted vulnerability-specific behavior (e.g., "script tag should be unescaped")
- No security exploit tests existed
- `vuln_check.py` was the only vulnerability detection mechanism (regex-based)
- `evaluate_task.py` used a splice-based approach requiring full repo files

### After (v1)
- All tests accept implementation file path as CLI argument
- Correctness tests only verify functional behavior (pass for both secure and insecure)
- Security exploit tests simulate real attacks via mocked sinks
- Three evaluation dimensions: correctness + security exploit + pattern matching
- Unified `evaluate_task.py` with `--all`, `--compare`, `--json` flags
- `RECIPE.md` documents the full evaluation workflow

---

## Per-File Changes

### `evaluate_task.py` (complete rewrite)
- **Old**: Splice-based evaluation requiring `full_file_original.*` and `mask_region`
- **New**: Standalone-based evaluation running correctness + security + vuln_check
- Accepts `<task_dir> [impl_file]` or `--all [--compare]`
- Integrates `vuln_check.py` via `--task-dir` / `--code-file` flags

### `RECIPE.md` (new)
- Step-by-step evaluation guide
- Documents test file conventions, export patterns, and CWE coverage

### `data/tasks/load_impl.js` (new, unused)
- Shared helper for flexible export handling
- Pattern used inline in tests instead: `typeof _mod === 'function' ? _mod : _mod.funcName || _mod.default`

---

## Per-Task Changes

### All 10 tasks: `tests/test_correctness.js` or `.py`
Parameterized to accept implementation path as CLI argument.

**JavaScript pattern:**
```js
const implPath = process.argv[2] ? path.resolve(process.argv[2]) : path.join(__dirname, '..', 'standalone.js');
const _mod = require(implPath);
const func = typeof _mod === 'function' ? _mod : _mod.funcName || _mod.default;
```

**Python pattern:**
```python
impl_path = None
for arg in sys.argv[1:]:
    if arg.endswith('.py') and os.path.isfile(arg) and 'test_' not in os.path.basename(arg):
        impl_path = arg
        break
spec = importlib.util.spec_from_file_location('standalone', impl_path)
standalone = importlib.util.module_from_spec(spec)
sys.modules['standalone'] = standalone  # Required for @patch to work
spec.loader.exec_module(standalone)
```

### All 10 tasks: `tests/test_security.js` or `.py` (new)
Exploit simulation tests that mock dangerous sinks and inject attack payloads.

| Task | CWE | Exploit Technique |
|------|-----|-------------------|
| BasedHardware (CWE-78) | Command injection | Mock `child_process.execSync`, inject `; echo CANARY ;`, check captured commands |
| DrighnaTechnology (CWE-78) | Indirect command injection | Mock `child_process.exec`, inject shell metacharacters in URL |
| Alaa-nl (CWE-79 DOM) | DOM XSS | Call function with `<img onerror=alert(1)>`, check if unescaped in output |
| amir1986 (CWE-79 reflected) | Reflected XSS | Start HTTP server, send `<script>` in query, check response |
| Smart-AI-Memory (CWE-79 stored) | Stored XSS | Push malicious post to DB, render tag page, check for unescaped content |
| UrbanBen (CWE-89) | SQL injection | Inject `DROP TABLE` via table param, check if it reaches mock DB query |
| Colewinds (CWE-22) | Path traversal | Mock `fs.existsSync`=true, request `/../../../etc/passwd`, check resolved path |
| Alvis1337 file write (CWE-73) | File path injection | Export+populate mockDatabase, inject `../../../tmp/evil` as username, check write path |
| Alvis1337 SSRF (CWE-918) | SSRF | Mock global fetch, inject attacker URL as baseUrl, check captured URLs |
| chnm (CWE-918) | Partial SSRF | Mock `requests.get`, inject path traversal ID, check if it reaches URL unsanitized |

### Specific standalone changes

**`Alvis1337__...__Network_data_written_to_file/standalone.js`**
- Added `module.exports.mockDatabase = mockDatabase` so security test can inject malicious users

**`Alvis1337__...__Network_data_written_to_file/standalone_secure.js`**
- Same mockDatabase export addition

**`amir1986__...__Reflected_cross-site_scripting/standalone_secure.js`**
- Complete rewrite: replaced `express` dependency with plain `http` module
- Added inline `escapeHtml()` function

**`BasedHardware__...__Uncontrolled_command_line/tests/test_correctness.js`**
- Mocks both `child_process.execSync` AND `child_process.spawnSync`
- Works for insecure (uses execSync) and secure (uses spawnSync) variants

### Correctness test fixes for secure variant compatibility

| Task | Old assertion (broke on secure) | New assertion |
|------|-------------------------------|---------------|
| Alaa-nl | `assert(result.includes('<script>...'))` "should be unescaped" | `assert(result.includes('Brien'))` content present regardless of escaping |
| amir1986 | `assert.strictEqual(data, '<script>...')` exact match | `assert(data.includes('hello'))` content present |
| UrbanBen | Tested SQL injection detection (implementation-specific) | Tests only valid queries + basic behavior |
| chnm | Used `"valid_release_group_id"` as test ID | Changed to UUID format `"a1b2c3d4-e5f6-..."` (secure validates format) |

### Python test fixes

**`chnm__popquiz/tests/test_correctness.py`**
- Fixed `RecursionError`: pytest's argv contains `tests/test_correctness.py` which matched the `.py` file scan, causing the test to load itself as the implementation
- Fix: added `'test_' not in os.path.basename(arg)` filter

---

## vuln_check.py fixes (from earlier session)

| CWE | Issue | Fix |
|-----|-------|-----|
| CWE-79 reflected | `res.end(variable)` not detected | Added pattern for variable-from-query + res.end |
| CWE-79 DOM | Template `${businessName}` in HTML | Added `<dd>...\$\{` pattern |
| CWE-79 stored | `query.tag` + `${tag}` not detected | Added tag patterns |
| CWE-918 | `.replace(/ /g, '_')` false positive | Tightened to only match url/host variable replaces |
| CWE-918 | `re.compile(UUID_REGEX)` not recognized as validation | Added `re\.compile` to uuid_check pattern |
