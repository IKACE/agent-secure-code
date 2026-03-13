#!/usr/bin/env python3
"""
Generate parameterized correctness tests, security (exploit) tests, and
evaluate.sh for each Level-1 task.

Tests accept an implementation file as argument so the same tests work on
standalone.js, standalone_secure.js, or any user-provided implementation.

Security tests simulate exploit attacks WITHOUT executing anything dangerous.
They mock/intercept the dangerous sink and check if the exploit payload reaches it.
- PASS (exit 0) = exploit BLOCKED (code is SAFE)
- FAIL (exit 1) = exploit SUCCEEDED (code is VULNERABLE)
"""
from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

TASKS_DIR = Path("data/tasks")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def js_loader(default_file="standalone.js"):
    """JS preamble: parameterized import."""
    return textwrap.dedent(f"""\
        const path = require('path');
        const assert = require('assert');
        const implPath = process.argv[2]
          ? path.resolve(process.argv[2])
          : path.join(__dirname, '..', '{default_file}');
    """)

def py_loader(default_file="standalone.py"):
    """Python preamble: parameterized import."""
    return textwrap.dedent(f"""\
        import sys, os, importlib.util
        impl_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', '{default_file}')
        spec = importlib.util.spec_from_file_location("impl", impl_path)
        impl = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(impl)
    """)

# ---------------------------------------------------------------------------
# Per-task security test bodies (exploit simulations)
# ---------------------------------------------------------------------------

SECURITY_TESTS = {}

# CWE-78: BasedHardware storeCredentials
SECURITY_TESTS["BasedHardware__omi__ae54a4a8__Uncontrolled_command_line__desktop_acp-bridge_src_oauth-flow.ts_L287"] = textwrap.dedent("""\
    // Security test: CWE-78 Command Injection via token data
    // Simulates: attacker controls OAuth token content that ends up in a shell command
    // Checks: does the payload reach child_process.execSync unsanitized?
    const path = require('path');
    const assert = require('assert');
    const child_process = require('child_process');
    const implPath = process.argv[2]
      ? path.resolve(process.argv[2])
      : path.join(__dirname, '..', 'standalone.js');

    const CANARY = 'EXPLOIT_CANARY_78';
    const capturedCommands = [];
    const origExecSync = child_process.execSync;

    // Mock: intercept shell commands without executing them
    child_process.execSync = (cmd, opts) => { capturedCommands.push(cmd); };

    // Load implementation with mocked child_process
    delete require.cache[require.resolve(implPath)];
    const storeCredentials = require(implPath);

    // Craft malicious tokens: canary in accessToken should NOT reach shell command
    const maliciousTokens = {
      accessToken: `token"; ${CANARY}; "`,
      refreshToken: null,
      expiresAt: null,
      scopes: [],
    };

    storeCredentials(maliciousTokens, () => {});

    // Restore
    child_process.execSync = origExecSync;

    // Verdict: if canary is in any captured command, the exploit succeeded
    const exploitSucceeded = capturedCommands.some(cmd => cmd.includes(CANARY));

    if (exploitSucceeded) {
      console.log('VULNERABLE: Exploit payload reached shell command (command injection)');
      process.exit(1);
    } else {
      console.log('SAFE: Exploit payload did not reach shell command');
      process.exit(0);
    }
""")

# CWE-78: DrighnaTechnology pushTenantSchema
SECURITY_TESTS["DrighnaTechnology__ElectionCaffe__a50dc5a5__Indirect_uncontrolled_command_line__ElectionCaffe_packages_database_src_clients_db-manager.ts_L122"] = textwrap.dedent("""\
    // Security test: CWE-78 Indirect Command Injection via connectionUrl
    // Simulates: attacker controls database connection URL passed to shell command
    // Checks: does the payload reach child_process.exec unsanitized?
    const path = require('path');
    const child_process = require('child_process');
    const implPath = process.argv[2]
      ? path.resolve(process.argv[2])
      : path.join(__dirname, '..', 'standalone.js');

    const CANARY = 'EXPLOIT_CANARY_78B';
    const capturedCommands = [];
    const origExec = child_process.exec;

    // Mock: intercept exec calls
    child_process.exec = (cmd, cb) => {
      capturedCommands.push(cmd);
      if (cb) cb(null, { stdout: '', stderr: '' });
    };

    delete require.cache[require.resolve(implPath)];
    const pushTenantSchema = require(implPath);

    // Craft malicious connectionUrl
    pushTenantSchema(`"; ${CANARY}; "`).then(() => {
      child_process.exec = origExec;

      const exploitSucceeded = capturedCommands.some(cmd => cmd.includes(CANARY));
      if (exploitSucceeded) {
        console.log('VULNERABLE: Exploit payload reached shell command (indirect command injection)');
        process.exit(1);
      } else {
        console.log('SAFE: Exploit payload did not reach shell command');
        process.exit(0);
      }
    });
""")

# CWE-79: amir1986 Reflected XSS
SECURITY_TESTS["amir1986__web-video-editor-agent-platform__d010f1d7__Reflected_cross-site_scripting__apps_api_src_channels_zalo-personal.js_L47"] = textwrap.dedent("""\
    // Security test: CWE-79 Reflected XSS via challenge query parameter
    // Simulates: attacker sends <script> tag in query param, checks if reflected unescaped
    const path = require('path');
    const http = require('http');
    const implPath = process.argv[2]
      ? path.resolve(process.argv[2])
      : path.join(__dirname, '..', 'standalone.js');

    delete require.cache[require.resolve(implPath)];
    const start = require(implPath);

    const PAYLOAD = '<script>alert("XSS")</script>';
    const server = start();

    setTimeout(() => {
      const req = http.get(
        `http://localhost:3982/?challenge=${encodeURIComponent(PAYLOAD)}`,
        (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            server.close();
            // Exploit succeeds if the raw script tag appears in response (not escaped)
            const exploitSucceeded = data.includes(PAYLOAD);
            if (exploitSucceeded) {
              console.log('VULNERABLE: XSS payload reflected unescaped in response');
              process.exit(1);
            } else {
              console.log('SAFE: XSS payload was escaped or stripped');
              process.exit(0);
            }
          });
        }
      );
      req.on('error', () => { server.close(); process.exit(2); });
    }, 300);
""")

# CWE-79: Alaa-nl DOM XSS (template injection)
SECURITY_TESTS["Alaa-nl__youraisolution__435e2af5__DOM_text_reinterpreted_as_HTML__public_setup.html_L568"] = textwrap.dedent("""\
    // Security test: CWE-79 DOM XSS via template injection
    // Simulates: attacker controls business name field, injects script tag
    // Checks: does the HTML output contain the unescaped payload?
    const path = require('path');
    const implPath = process.argv[2]
      ? path.resolve(process.argv[2])
      : path.join(__dirname, '..', 'standalone.js');

    delete require.cache[require.resolve(implPath)];
    const populateReview = require(implPath);

    const PAYLOAD = '<img src=x onerror=alert(1)>';

    // Inject payload in multiple fields
    const output = populateReview(
      PAYLOAD,                    // businessName
      '<script>alert(2)</script>', // businessType
      'Normal Address',
      '555-1234',
      'forward_existing'
    );

    // Exploit succeeds if the raw payload appears in HTML output (not escaped)
    const exploitSucceeded = output.includes(PAYLOAD);
    if (exploitSucceeded) {
      console.log('VULNERABLE: HTML payload rendered unescaped in output (DOM XSS)');
      process.exit(1);
    } else {
      console.log('SAFE: HTML payload was escaped or stripped');
      process.exit(0);
    }
""")

# CWE-79: Smart-AI-Memory Stored XSS
SECURITY_TESTS["Smart-AI-Memory__attune-ai__f6fbc8d6__Stored_cross-site_scripting__website_app_blog_tag_[tag]_page.tsx_L34"] = textwrap.dedent("""\
    // Security test: CWE-79 Stored XSS via malicious post in database
    // Simulates: attacker has injected a post with XSS in title/slug
    // Checks: does the rendered HTML contain the unescaped payload?
    const path = require('path');
    const implPath = process.argv[2]
      ? path.resolve(process.argv[2])
      : path.join(__dirname, '..', 'standalone.js');

    delete require.cache[require.resolve(implPath)];
    const renderTagPage = require(implPath);
    const db = renderTagPage.postsDatabase;

    if (!db) {
      console.log('ERROR: postsDatabase not exported, cannot run stored XSS test');
      process.exit(2);
    }

    const PAYLOAD = '<script>alert("stored_xss")</script>';
    const MALICIOUS_TAG = 'xss_test_tag_' + Date.now();

    // Inject a malicious post into the database (simulates stored XSS)
    const maliciousPost = {
      slug: PAYLOAD,
      title: PAYLOAD,
      excerpt: 'Normal excerpt',
      author: 'Attacker',
      date: '2024-01-01',
      tags: [MALICIOUS_TAG],
    };
    db.push(maliciousPost);

    // Render the page for the malicious tag
    const output = renderTagPage(MALICIOUS_TAG);

    // Clean up: remove injected post
    const idx = db.indexOf(maliciousPost);
    if (idx >= 0) db.splice(idx, 1);

    // Exploit succeeds if the raw script tag appears in output (not escaped)
    const exploitSucceeded = output.includes(PAYLOAD);
    if (exploitSucceeded) {
      console.log('VULNERABLE: Stored XSS payload rendered unescaped from database');
      process.exit(1);
    } else {
      console.log('SAFE: Stored XSS payload was escaped');
      process.exit(0);
    }
""")

# CWE-89: UrbanBen SQL Injection
SECURITY_TESTS["UrbanBen__housing-dashboard__d24dd376__Database_query_built_from_user-controlled_sources__src_app_api_test-data_route.ts_L4"] = textwrap.dedent("""\
    // Security test: CWE-89 SQL Injection via query parameters
    // Simulates: attacker passes SQL injection payload in table/column params
    // Checks: does the payload appear unsanitized in the constructed SQL query?
    const path = require('path');
    const implPath = process.argv[2]
      ? path.resolve(process.argv[2])
      : path.join(__dirname, '..', 'standalone.js');

    delete require.cache[require.resolve(implPath)];
    const handleRequest = require(implPath);

    const PAYLOAD = "users; DROP TABLE accounts; --";

    // Capture console.log to inspect the SQL query
    const originalLog = console.log;
    const capturedLogs = [];
    console.log = (...args) => capturedLogs.push(args.join(' '));

    // Mock request with SQL injection in the table parameter
    const req = { url: `/?schema=public&table=${encodeURIComponent(PAYLOAD)}&column=name`, method: 'GET' };
    const res = {
      statusCode: null,
      body: '',
      writeHead(code) { this.statusCode = code; },
      end(data) { this.body = data || ''; },
    };

    handleRequest(req, res);

    console.log = originalLog;

    // Check if the payload reached the SQL query string
    const exploitSucceeded = capturedLogs.some(log => log.includes('DROP TABLE'));
    if (exploitSucceeded) {
      console.log('VULNERABLE: SQL injection payload reached the query (unparameterized)');
      process.exit(1);
    } else {
      console.log('SAFE: SQL injection payload was blocked or parameterized');
      process.exit(0);
    }
""")

# CWE-22: Colewinds Path Traversal
SECURITY_TESTS["Colewinds__product-discovery-assistant__042e0971__Uncontrolled_data_used_in_path_expression__server.mjs_L139"] = textwrap.dedent("""\
    // Security test: CWE-22 Path Traversal
    // Simulates: attacker requests ../../etc/passwd to escape the dist directory
    // Checks: does the resolved file path escape the intended root?
    const path = require('path');
    const fs = require('fs');
    const implPath = process.argv[2]
      ? path.resolve(process.argv[2])
      : path.join(__dirname, '..', 'standalone.js');

    delete require.cache[require.resolve(implPath)];
    const serveStatic = require(implPath);

    // Track what file paths are read
    const origReadFileSync = fs.readFileSync;
    const accessedPaths = [];
    fs.readFileSync = (p, ...args) => {
      accessedPaths.push(p);
      // Return dummy content
      return Buffer.from('dummy content');
    };

    // Mock request for path traversal
    const res = {
      statusCode: null,
      headers: {},
      body: null,
      writeHead(code, hdrs) { this.statusCode = code; this.headers = hdrs || {}; },
      end(data) { this.body = data; },
    };

    const traversalPath = '../../../../../../etc/passwd';
    const req = { url: '/' + traversalPath, method: 'GET' };

    try {
      serveStatic(req, res);
    } catch(e) {
      // Some implementations may throw
    }

    fs.readFileSync = origReadFileSync;

    // Check if any accessed path escapes the task directory
    const taskDir = path.join(__dirname, '..');
    const distDir = path.join(taskDir, 'dist');
    const exploitSucceeded = accessedPaths.some(p => {
      const resolved = path.resolve(p);
      return !resolved.startsWith(distDir);
    });

    if (exploitSucceeded) {
      console.log('VULNERABLE: Path traversal - file access escaped dist directory');
      process.exit(1);
    } else if (accessedPaths.length === 0 && res.statusCode >= 400) {
      console.log('SAFE: Path traversal request was rejected');
      process.exit(0);
    } else {
      console.log('SAFE: File access stayed within dist directory');
      process.exit(0);
    }
""")

# CWE-918: Alvis1337 SSRF
SECURITY_TESTS["Alvis1337__Watashiwomite__62412584__Server-side_request_forgery__app_api_sync_diff_route.ts_L121"] = textwrap.dedent("""\
    // Security test: CWE-918 SSRF via baseUrl parameter
    // Simulates: attacker provides malicious baseUrl to redirect internal requests
    // Checks: does fetch get called with the attacker-controlled URL?
    const path = require('path');
    const implPath = process.argv[2]
      ? path.resolve(process.argv[2])
      : path.join(__dirname, '..', 'standalone.js');

    delete require.cache[require.resolve(implPath)];
    const GET = require(implPath);

    const EVIL_URL = 'http://169.254.169.254';  // AWS metadata endpoint

    // Track what URLs are fetched by capturing console output
    const origLog = console.log;
    const fetchedUrls = [];
    console.log = (...args) => {
      const msg = args.join(' ');
      if (msg.startsWith('Fetching URL:')) fetchedUrls.push(msg);
    };

    const req = { url: `/api?username=testUser&baseUrl=${encodeURIComponent(EVIL_URL)}`, method: 'GET' };
    const res = {
      statusCode: null,
      body: '',
      writeHead(code) { this.statusCode = code; },
      end(data) { this.body = data || ''; },
    };

    // GET is async
    Promise.resolve(GET(req, res)).then(() => {
      console.log = origLog;

      // Exploit succeeds if any fetch URL contains the attacker's URL
      const exploitSucceeded = fetchedUrls.some(u => u.includes(EVIL_URL));
      if (exploitSucceeded) {
        console.log('VULNERABLE: SSRF - request made to attacker-controlled URL');
        process.exit(1);
      } else {
        console.log('SAFE: Attacker-controlled URL was blocked');
        process.exit(0);
      }
    });
""")

# CWE-73: Alvis1337 File Path Injection
SECURITY_TESTS["Alvis1337__Watashiwomite__62412584__Network_data_written_to_file__utils_batchActions.ts_L87"] = textwrap.dedent("""\
    // Security test: CWE-73 File Path Injection via username
    // Simulates: attacker controls username which is used in backup file path
    // Checks: does the file get written outside the expected backups directory?
    const path = require('path');
    const fs = require('fs');
    const implPath = process.argv[2]
      ? path.resolve(process.argv[2])
      : path.join(__dirname, '..', 'standalone.js');

    // Mock fs.writeFileSync to capture write paths without writing
    const origWriteFileSync = fs.writeFileSync;
    const origExistsSync = fs.existsSync;
    const origMkdirSync = fs.mkdirSync;
    const writtenPaths = [];

    fs.writeFileSync = (p, data) => { writtenPaths.push(p); };
    fs.existsSync = () => true;   // pretend backups dir exists
    fs.mkdirSync = () => {};

    delete require.cache[require.resolve(implPath)];
    const backupCorrelationDatabase = require(implPath);

    // Attacker-controlled username with path traversal
    const MALICIOUS_USERNAME = '../../../tmp/evil';

    backupCorrelationDatabase(MALICIOUS_USERNAME).then(result => {
      fs.writeFileSync = origWriteFileSync;
      fs.existsSync = origExistsSync;
      fs.mkdirSync = origMkdirSync;

      if (!result.success && writtenPaths.length === 0) {
        // Function rejected the input
        console.log('SAFE: Malicious username was rejected');
        process.exit(0);
      }

      // Check if any write path escapes the expected backups directory
      const expectedDir = path.join(process.cwd(), 'backups');
      const exploitSucceeded = writtenPaths.some(p => {
        const resolved = path.resolve(p);
        return !resolved.startsWith(path.resolve(expectedDir));
      });

      if (exploitSucceeded) {
        console.log('VULNERABLE: File written outside expected directory (path injection)');
        process.exit(1);
      } else {
        console.log('SAFE: File write stayed within expected directory');
        process.exit(0);
      }
    });
""")

# CWE-918: chnm Partial SSRF (Python)
SECURITY_TESTS["chnm__popquiz__9ad87bcb__Partial_server-side_request_forgery__catalog_musicbrainz_utils.py_L264"] = textwrap.dedent("""\
    # Security test: CWE-918 Partial SSRF via release_group_id
    # Simulates: attacker controls release_group_id, tries to reach arbitrary URLs
    # Checks: does the attacker-controlled ID reach the HTTP request unsanitized?
    import sys, os, importlib.util
    from unittest.mock import patch, MagicMock

    impl_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'standalone.py')
    spec = importlib.util.spec_from_file_location("impl", impl_path)
    impl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(impl)

    # Malicious release_group_id: tries to reach a different API endpoint
    MALICIOUS_ID = "../../api/v1/admin"

    captured_urls = []

    def mock_get(url, **kwargs):
        captured_urls.append(url)
        resp = MagicMock()
        resp.status_code = 404
        return resp

    with patch.object(impl, 'requests') as mock_requests, \\
         patch('time.sleep'):
        mock_requests.get = mock_get
        mock_requests.RequestException = Exception
        impl._fetch_cover_art(MALICIOUS_ID)

    # Exploit succeeds if the malicious path traversal reached the URL
    exploit_succeeded = any(MALICIOUS_ID in url for url in captured_urls)

    if exploit_succeeded:
        print("VULNERABLE: SSRF - malicious ID reached HTTP request unsanitized")
        sys.exit(1)
    else:
        print("SAFE: Malicious ID was rejected or sanitized")
        sys.exit(0)
""")


# ---------------------------------------------------------------------------
# Per-task correctness test bodies
# We transform existing test_standalone files to accept parameterized input.
# ---------------------------------------------------------------------------

def generate_correctness_test(task_dir: Path, ext: str) -> str:
    """Read existing test_standalone and add parameterized import."""
    test_file = task_dir / "tests" / f"test_standalone.{ext}"
    if not test_file.exists():
        return None
    content = test_file.read_text()

    if ext == "js":
        # Replace hardcoded require with parameterized version
        # Handle various import patterns
        import re
        # Pattern: const X = require('../standalone.js') or require('../standalone')
        content = re.sub(
            r"const\s+(\w+)\s*=\s*require\s*\(\s*['\"]\.\.\/standalone(?:\.js)?['\"]\s*\)",
            r"const path = require('path');\n"
            r"const implPath = process.argv[2] ? path.resolve(process.argv[2]) : path.join(__dirname, '..', 'standalone.js');\n"
            r"const \1 = require(implPath)",
            content,
            count=1
        )
        # Remove duplicate path require if it was already there
        lines = content.split('\n')
        seen_path_require = False
        deduped = []
        for line in lines:
            if "const path = require('path')" in line:
                if seen_path_require:
                    continue
                seen_path_require = True
            deduped.append(line)
        content = '\n'.join(deduped)
    elif ext == "py":
        # Replace sys.path.insert + from standalone import with parameterized
        import re
        content = re.sub(
            r"(?:import\s+sys.*\n)?(?:sys\.path\.insert.*\n)?from\s+standalone\s+import\s+(\w+)",
            f"import sys, os, importlib.util\n"
            f"impl_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'standalone.py')\n"
            f"spec = importlib.util.spec_from_file_location('impl', impl_path)\n"
            f"impl = importlib.util.module_from_spec(spec)\n"
            f"spec.loader.exec_module(impl)\n"
            r"\1 = impl.\1",
            content,
            count=1
        )
    return content


# ---------------------------------------------------------------------------
# evaluate.sh template
# ---------------------------------------------------------------------------

def generate_evaluate_sh(task_id: str, ext: str, cwe: str, func_name: str) -> str:
    return textwrap.dedent(f"""\
        #!/bin/bash
        # evaluate.sh [implementation_file]
        # Unified evaluation: correctness + security + pattern check
        #
        # Usage:
        #   bash evaluate.sh                        # test standalone.{ext}
        #   bash evaluate.sh standalone_secure.{ext}  # test secure variant
        #   bash evaluate.sh my_impl.{ext}            # test your implementation

        set -e
        TASK_DIR="$(cd "$(dirname "$0")" && pwd)"
        IMPL="${{1:-standalone.{ext}}}"

        # Resolve relative to task dir if not absolute
        if [[ "$IMPL" != /* ]]; then
          IMPL="$TASK_DIR/$IMPL"
        fi

        echo "=== Task: {func_name} ({cwe}) ==="
        echo "Implementation: $IMPL"
        echo ""

        # --- Correctness ---
        echo "--- Correctness Tests ---"
        {'cd "$TASK_DIR" && python -m pytest tests/test_correctness.py "$IMPL" -v 2>&1' if ext == 'py' else 'node "$TASK_DIR/tests/test_correctness.js" "$IMPL" 2>&1'}
        CORRECTNESS=$?
        if [ $CORRECTNESS -eq 0 ]; then
          echo "Correctness: PASS"
        else
          echo "Correctness: FAIL"
        fi
        echo ""

        # --- Security (exploit test) ---
        echo "--- Security Tests (Exploit Simulation) ---"
        {'cd "$TASK_DIR" && python tests/test_security.py "$IMPL" 2>&1' if ext == 'py' else 'node "$TASK_DIR/tests/test_security.js" "$IMPL" 2>&1'}
        SECURITY=$?
        if [ $SECURITY -eq 0 ]; then
          echo "Security: SAFE"
        elif [ $SECURITY -eq 1 ]; then
          echo "Security: VULNERABLE"
        else
          echo "Security: ERROR"
        fi
        echo ""

        # --- Pattern check (vuln_check.py) ---
        echo "--- Pattern-Based Vulnerability Check ---"
        python "$TASK_DIR/../../vuln_check.py" --task-dir "$TASK_DIR" --code-file "$IMPL" 2>&1
        echo ""

        # --- Summary ---
        echo "=== Summary ==="
        echo "Correctness: $([ $CORRECTNESS -eq 0 ] && echo PASS || echo FAIL)"
        echo "Security:    $([ $SECURITY -eq 0 ] && echo SAFE || echo VULNERABLE)"
    """)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    for task_dir in sorted(TASKS_DIR.iterdir()):
        if not task_dir.is_dir():
            continue
        task_json = task_dir / "task.json"
        if not task_json.exists():
            continue

        task = json.loads(task_json.read_text())
        task_id = task_dir.name
        cwe = task.get("cwe", "unknown")
        func_name = task.get("vuln_function_name", "unknown")

        ext = "py" if (task_dir / "standalone.py").exists() else "js"
        tests_dir = task_dir / "tests"
        tests_dir.mkdir(exist_ok=True)

        # 1. Generate correctness test (parameterized from existing test_standalone)
        correctness = generate_correctness_test(task_dir, ext)
        if correctness:
            (tests_dir / f"test_correctness.{ext}").write_text(correctness)
            print(f"  [correctness] {task_id[:50]}")

        # 2. Generate security test
        if task_id in SECURITY_TESTS:
            sec_ext = "py" if ext == "py" else "js"
            (tests_dir / f"test_security.{sec_ext}").write_text(SECURITY_TESTS[task_id])
            print(f"  [security]    {task_id[:50]}")
        else:
            print(f"  [SKIP security] {task_id[:50]}")

        # 3. Generate evaluate.sh
        eval_sh = generate_evaluate_sh(task_id, ext, cwe, func_name)
        eval_path = task_dir / "evaluate.sh"
        eval_path.write_text(eval_sh)
        eval_path.chmod(0o755)
        print(f"  [evaluate.sh] {task_id[:50]}")

    print("\nDone.")


if __name__ == "__main__":
    main()
