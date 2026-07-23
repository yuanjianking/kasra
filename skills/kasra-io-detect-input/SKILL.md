---
name: kasra-io-detect-input
description: Run input detection system tests for the Kasra AI security gateway, verifying I-series rules fire as expected
metadata:
  type: skill
---

# Kasra IO Detect — Input Detection System Tests

## Overview

Call the Kasra API (`POST /v1/scan/input`) to execute I-series input detection test cases one by one, verifying that the input security gateway's detection rules fire as expected.

Test cases are defined in `system-test/io-tests/` in three language versions:
- `01-input-detection-zh.md` — Chinese
- `01-input-detection-en.md` — English
- `01-input-detection-jp.md` — Japanese

Use the `-l zh|en|jp` parameter to specify the language (default: `zh`).

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

For each I-series test case, send the user **prompt** directly to the Kasra input detection API:

```bash
curl -s -X POST http://localhost:8090/v1/scan/input \
  -H "X-API-Key: kasra-dev-api-key-change-in-prod" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "<user prompt>",
    "user_id": "io-test",
    "session_id": "tc-io-<case number>",
    "request_id": "<test case ID>"
  }' | python3 -m json.tool
```

The `triggered_rules` array in the response should contain the expected rule IDs and actions.

## Test Case Structure

Each test case contains:
- **Test Case ID**: TC-IO-<number>
- **Prompt**: The text the user enters in Claude Code
- **Expected Input Detection Result**: The I-rule ID and action expected to fire (e.g. `I-01 → block`)

## Expected Action Meanings

| Action | Meaning | Description |
|--------|---------|-------------|
| `block` | Blocked | Content is intercepted, processing stops |
| `warn` | Warning | Alert triggered but content passes through |
| `redact` | Redacted | Sensitive PII info is masked/replaced |
| `clean` | Sanitized | Special characters are normalized/removed |
| `truncate` | Truncated | Overlong content is trimmed |
| `soft_allow` | Reduced severity | Declared anonymized data lowers detection severity |
| `dynamic` | Dynamic escalation | Declared PII content triggers escalation |

## API Response Structure

```json
{
  "blocked": false,
  "action": "warn",
  "severity": "P0",
  "triggered_rules": [
    {
      "rule_id": "I-01",
      "rule_name": "GitHub Token Detection",
      "severity": "P0",
      "action": "block",
      "match_count": 1,
      "matched_text": "ghp_..."
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
| User prompt | `POST /v1/scan/input` | `triggered_rules[].rule_id` contains expected rule ID |

For each test case:
1. Read the prompt from the test file
2. Call the `/v1/scan/input` API
3. Check that `triggered_rules` contains the expected rule
4. Verify each triggered rule's `action` matches expectations
5. Record result as `✅ PASS` or `❌ FAIL`

### Summary Output

After all tests complete, output a summary table:

```
📊 Kasra Input Detect Test Summary
━━━━━━━━━━━━━━━━━━━
I-series: X/Y passed

❌ Failed cases:
- TC-IO-<number>: expected [I-xx → action], got no trigger
- ...
```

## Batch Execution Suggestions

For large test suites, use a Workflow for parallel execution:

```javascript
const inputCases = [...];  // I-series test case array

phase('Input Detection');
const iResults = await pipeline(inputCases, (tc) =>
  agent(`Input detection: ${tc.id} — ${tc.prompt.slice(0, 60)}...`, {
    label: tc.id,
    phase: 'Input Detection',
    schema: SCAN_RESPONSE_SCHEMA,
  })
);
```

## Language Selection

Specify the language version when invoking:
- `kasra-io-detect-input -l zh` — Chinese (default)
- `kasra-io-detect-input -l en` — English
- `kasra-io-detect-input -l jp` — Japanese

## Rule Category Reference

| Range | Rules | Category |
|-------|-------|----------|
| I-01~I-10 | Credential Leak Detection | GitHub/OpenAI/Claude/AWS/Stripe/password/private key/JWT/connection string/wallet |
| I-11~I-20 | PII Detection | phone/ID/email/credit card/passport/IBAN/IP/name/DOB/medical |
| I-21~I-31 | Injection Attack Detection | Prompt injection/jailbreak/OS command/SQL/NoSQL/SSTI/XXE/LDAP/encoding bypass/SSRF/prompt extraction |
| I-32~I-34 | Encoding Bypass | Unicode obfuscation/Base64/Hex/ROT13/non-linguistic probing |
| I-35~I-41 | File Risk | sensitive file/credential repo/large file/ZipSlip/proprietary code/bomb |
| I-42~I-48 | Context Security | pollution mark/truncation/control char/authorization/dynamic escalation/split attack/reset bypass |
| I-49~I-57 | Social Engineering/Malicious Code | Social Eng/SecurityBypass/reverse shell/supply chain/data exfil/ransomware/cryptominer/phishing/escalation |

## FAQs

| Issue | Cause | Solution |
|-------|-------|----------|
| API returns `401` | API Key mismatch | Check the actual key in settings.local.json |
| `triggered_rules` is empty | Rules not loaded from DB | Call `POST /v1/rules/reload` and check `/health` `rules_loaded` |
| Port unreachable | Service not running or port differs | Run `ss -tlnp \| grep -E '808[0-9]\|809[0-9]'` |
| Missing rules | Database is empty | Run SDK `load_rules.py` to initialize the rule database |

## Pre-Verified Test Results

| Case | Input | Expected | Actual | Status |
|------|-------|----------|--------|--------|
| TC-IO-001 | GitHub Token `ghp_xxxxxxxx...` | I-01 → block | I-01 → block | ✅ |
| TC-IO-011 | Phone `13800138000` | I-11 → redact | I-11 → redact | ✅ |
| TC-IO-022 | Prompt injection | I-21 → block | I-21 → block | ✅ |
| TC-IO-053 | Reverse shell | I-51 → block | I-51 → block | ✅ |

## Pre-flight Checklist

Before running tests, confirm:
- [ ] Kasra API is running (`curl http://localhost:8090/health`)
- [ ] API Key is valid (`curl -s http://localhost:8090/v1/rules -H "X-API-Key: kasra-dev-api-key-change-in-prod"`)
- [ ] Rules are loaded (`rules_loaded > 0` in `/health`)
- [ ] Test case files exist (`system-test/io-tests/01-input-detection-*.md`)
