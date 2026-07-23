---
name: kasra-io-detect-output
description: Run output detection system tests for the Kasra AI security gateway, verifying O-series rules fire as expected
metadata:
  type: skill
---

# Kasra IO Detect — Output Detection System Tests

## Overview

Call the Kasra API (`POST /v1/scan/output`) to execute O-series output detection test cases one by one, verifying that the output security gateway's detection rules fire as expected.

Test cases are defined in `system-test/io-tests/` in three language versions:
- `01-output-detection-zh.md` — Chinese
- `01-output-detection-en.md` — English
- `01-output-detection-jp.md` — Japanese

Use the `-l zh|en|jp` parameter to specify the language (default: `zh`).

### Key Difference from Input Detection

O-series test case tables have **three columns**:
| Test Case ID | User Prompt Entered in Claude Code | AI Generated Response / Code | Expected Output Detection Result |

Each test case includes a pre-defined **AI Generated Response / Code** column. There is **no need to call an LLM** — simply send the response content directly to the output detection API.

## Connection Configuration

| Parameter | Value |
|-----------|-------|
| API Address | `http://localhost:8090` |
| API Key | `kasra-dev-api-key-change-in-prod` |
| API Version Header | `Content-Type: application/json` |

Verify connectivity:
```bash
curl http://localhost:8090/health
curl -s http://localhost:8090/v1/rules -H "X-API-Key: kasra-dev-api-key-change-in-prod" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'{len(d.get(\"rules\",[]))} rules loaded')"
```

> ⚠️ If the API Key/port differ, check the `X-API-Key` and port configuration in `.claude/settings.local.json`.

## Test Procedure

### Single Test Case

For each O-series test case, send the **AI Generated Response / Code** content defined in the test case directly to the Kasra output detection API:

```bash
curl -s -X POST http://localhost:8090/v1/scan/output \
  -H "X-API-Key: kasra-dev-api-key-change-in-prod" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "<AI generated response/code>",
    "user_id": "io-test",
    "session_id": "tc-out-<case number>",
    "request_id": "<test case ID>"
  }' | python3 -m json.tool
```

> ⚠️ This endpoint validates the **output content** (AI generated response/code), not the user prompt. Test cases already contain pre-defined output content, so **no LLM call is needed**.

## Test Case Structure

Each test case contains:
- **Test Case ID**: TC-OUT-<number>
- **Prompt**: The text the user enters in Claude Code (for reference only)
- **AI Generated Response / Code**: The content scanned during output detection (this is what gets sent to the API)
- **Expected Output Detection Result**: The O-rule ID and action expected to fire (e.g. `O-01 → warn`)

## Expected Action Meanings

| Action | Meaning | Description |
|--------|---------|-------------|
| `block` | Blocked | Content is intercepted, processing stops |
| `warn` | Warning | Alert triggered but content passes through |
| `redact` | Redacted | Sensitive PII info is masked/replaced |

## API Response Structure

```json
{
  "blocked": false,
  "action": "warn",
  "severity": "P0",
  "triggered_rules": [
    {
      "rule_id": "O-01",
      "rule_name": "Dangerous Function Call",
      "severity": "P0",
      "action": "warn",
      "match_count": 1,
      "matched_text": "eval(expr)"
    }
  ],
  "redacted_content": null,
  "execution_time_ms": 12.34
}
```

## Test Verification Logic

### Per-Case Verification

| Input Content | API Endpoint | Verification Point |
|--------------|-------------|-------------------|
| "AI Generated Response / Code" from test case | `POST /v1/scan/output` | `triggered_rules[].rule_id` contains expected rule ID |

For each test case:
1. Read the "AI Generated Response / Code" column from the test file
2. Call the `/v1/scan/output` API
3. Check that `triggered_rules` contains the expected rule
4. Verify each triggered rule's `action` matches expectations
5. Record result as `✅ PASS` or `❌ FAIL`

### Summary Output

After all tests complete, output a summary table:

```
📊 Kasra Output Detect Test Summary
━━━━━━━━━━━━━━━━━━━
O-series: X/Y passed

❌ Failed cases:
- TC-OUT-<number>: expected [O-xx → action], got no trigger
- ...
```

## Batch Execution Suggestions

For large test suites, use a Workflow for parallel execution:

```javascript
const outputCases = [...]; // O-series test case array

phase('Output Detection');
const oResults = await pipeline(outputCases, (tc) =>
  agent(`Output detection: ${tc.id} — send response content to /v1/scan/output`, {
    label: tc.id,
    phase: 'Output Detection',
    schema: SCAN_RESPONSE_SCHEMA,
  })
);
```

## Language Selection

Specify the language version when invoking:
- `kasra-io-detect-output -l zh` — Chinese (default)
- `kasra-io-detect-output -l en` — English
- `kasra-io-detect-output -l jp` — Japanese

## Rule Category Reference

| Range | Rules | Category |
|-------|-------|----------|
| O-01~O-17 | Output Code Security | eval/dangerous shell/OS cmd/SQL injection/NoSQL/empty exception/insecure random/XXE/SSTI/LDAP/deserialization/SSRF/cert validation/prototype pollution/path traversal/ReDoS/XSS |
| O-18~O-22 | Output Credential/Key | credential leak/hardcoded keys/test credentials/copyright/internal secrets |
| O-23~O-26 | Output Security Config | DEBUG/ALLOWED_HOSTS/CORS/sensitive logging/hardcoded IP/file permissions |
| O-27~O-32 | Output Design Flaws | TOCTOU/memory safety/error leak/insecure protocol/obfuscated code/JWT flaws |
| O-33~O-37 | Output Supply Chain | dependency confusion/CVE dependencies/suspicious links/unpinned versions/geo-restricted mirrors |
| O-38~O-42 | Output Content Safety | harmful content/malicious code/training data/PII output/hallucinated references |
| O-43~O-53 | Compliance / i18n | crypto export/cross-border data/content moderation/GDPR audit/weak crypto/a11y/i18n/timezone/oversized output/audit log/cascade delete |

## Per-Rule Test Coverage

| Rule | Test Cases | Detection Content Type |
|------|-----------|----------------------|
| O-01 | TC-OUT-001~005 | Dangerous function calls (eval/exec/assert) |
| O-02 | TC-OUT-006~009 | Destructive shell commands (rm -rf/dd/mkfs/shutdown) |
| O-03 | TC-OUT-010~014 | OS command injection (subprocess/exec/Runtime) |
| O-04 | TC-OUT-015~018 | SQL string concatenation |
| O-05 | TC-OUT-019~021 | MongoDB $where/$ne/$regex injection |
| O-06 | TC-OUT-022~025 | Empty exception handlers (except:pass) |
| O-07 | TC-OUT-026~029 | Insecure randomness (random/Math.random) |
| O-08 | TC-OUT-030~032 | XXE (lxml/DocumentBuilder without protection) |
| O-09 | TC-OUT-033~036 | SSTI (render_template_string) |
| O-10 | TC-OUT-037~039 | LDAP filter concatenation |
| O-11 | TC-OUT-040~044 | Unsafe deserialization (pickle/yaml) |
| O-12 | TC-OUT-045~048 | SSRF (requests.get/axios with user URLs) |
| O-13 | TC-OUT-049~051 | Certificate validation disabled (verify=False) |
| O-14 | TC-OUT-052~054 | Prototype pollution (__proto__/_.merge) |
| O-15 | TC-OUT-055~057 | Path traversal (user input concatenation) |
| O-16 | TC-OUT-058~060 | ReDoS (catastrophic backtracking regex) |
| O-17 | TC-OUT-061~063 | XSS (innerHTML/document.write) |
| O-18 | TC-OUT-064~068 | Credential leak in output |
| O-19 | TC-OUT-069~072 | Hardcoded crypto keys |
| O-20 | TC-OUT-073~078 | Test/dummy credentials |
| O-21 | TC-OUT-079~082 | Copyright/license text |
| O-22 | TC-OUT-083~086 | Internal secret markers |
| O-23 | TC-OUT-087~092 | Dangerous production config (DEBUG/ALLOWED_HOSTS) |
| O-24 | TC-OUT-093~096 | Logging sensitive info |
| O-25 | TC-OUT-097~100 | Hardcoded private IP |
| O-26 | TC-OUT-101~104 | Unsafe file permissions (chmod 777) |
| O-27 | TC-OUT-105~107 | TOCTOU race conditions |
| O-28 | TC-OUT-108~112 | Memory safety (gets/strcpy) |
| O-29 | TC-OUT-113~116 | Error leak (str(e)/stack) |
| O-30 | TC-OUT-117~120 | Insecure protocols (FTP/telnet/SSLv3) |
| O-31 | TC-OUT-121~123 | Obfuscated code (eval(base64)) |
| O-32 | TC-OUT-124~127 | JWT flaws (alg:none/weak key) |
| O-33 | TC-OUT-128~130 | Dependency confusion |
| O-34 | TC-OUT-131~133 | Known CVE dependencies |
| O-35 | TC-OUT-134~136 | Suspicious/phishing links |
| O-36 | TC-OUT-137~139 | Unpinned dependency versions |
| O-37 | TC-OUT-140~142 | Geo-restricted mirror sources |
| O-38 | TC-OUT-143~145 | Harmful/illegal content |
| O-39 | TC-OUT-146~150 | Weaponized malicious code |
| O-40 | TC-OUT-151~153 | Training data extraction |
| O-41 | TC-OUT-154~158 | PII in output |
| O-42 | TC-OUT-159~161 | Hallucinated references |
| O-43 | TC-OUT-162~166 | Crypto export control |
| O-44 | TC-OUT-167~170 | Cross-border data transfer |
| O-45 | TC-OUT-171~173 | Content moderation missing |
| O-46 | TC-OUT-174~176 | GDPR audit missing |
| O-47 | TC-OUT-177~182 | Weak crypto algorithms |
| O-48 | TC-OUT-190~192 | Accessibility violations |
| O-49 | TC-OUT-193~195 | Hardcoded i18n strings |
| O-50 | TC-OUT-196~198 | Locale/timezone hardcoded |
| O-51 | TC-OUT-199~201 | Oversized output |
| O-52 | TC-OUT-183~185 | Audit log missing |
| O-53 | TC-OUT-186~189 | Cascade delete missing |

## FAQs

| Issue | Cause | Solution |
|-------|-------|----------|
| API returns `401` | API Key mismatch | Check the actual key in settings.local.json |
| `triggered_rules` is empty | Rules not loaded from DB | Call `POST /v1/rules/reload` and check `/health` `rules_loaded` |
| Port unreachable | Service not running or port differs | Run `ss -tlnp \| grep -E '808[0-9]\|809[0-9]'` |
| Missing rules | Database is empty | Run SDK `load_rules.py` to initialize the rule database |
| Code format in test cases | Markdown may contain escape characters | Ensure correct handling of `\n`, backticks when reading |

## Pre-flight Checklist

Before running tests, confirm:
- [ ] Kasra API is running (`curl http://localhost:8090/health`)
- [ ] API Key is valid (`curl -s http://localhost:8090/v1/rules -H "X-API-Key: kasra-dev-api-key-change-in-prod"`)
- [ ] Rules are loaded (`rules_loaded > 0` in `/health`)
- [ ] Test case files exist (`system-test/io-tests/01-output-detection-*.md`)
