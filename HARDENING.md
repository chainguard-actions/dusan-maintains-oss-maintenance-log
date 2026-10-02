<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log/v1.6.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log/v1.6.0** was hardened automatically. 7 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Multiple ${{ inputs.* }} expressions are directly interpolated inside a PowerShell run: block. Specifically, ${{ inputs.evidence-dir }} and ${{ inputs.config-file }} are embedded directly in the shell script, allowing an attacker who controls these inputs to inject arbitrary PowerShell commands. Offending lines: `$dir = "${{ inputs.evidence-dir }}"` and `$cfg = "${{ inputs.config-file }}"`.

Locations:

- `action.yml:50`
- `action.yml:51`

### script-injection (severity: high)

Rule (a): Multiple ${{ inputs.* }} expressions are directly interpolated inside a bash run: block in cli/action.yml. Offending patterns include: `if [ "${{ inputs.include-dev }}" = "true" ]`, `${{ inputs.threshold }}` used in conditions and as a CLI argument, and `oss-health-scan ${{ inputs.path }}` (twice). Any of these inputs can contain shell metacharacters that execute arbitrary commands before the shell ever sees them.

Locations:

- `cli/action.yml:43`
- `cli/action.yml:46`
- `cli/action.yml:51`
- `cli/action.yml:55`
- `cli/action.yml:65`
- `cli/action.yml:68`
- `cli/action.yml:71`

### github-env-injection (severity: high)

In action.yml, the PowerShell variables $dir and $cfg are set directly from ${{ inputs.evidence-dir }} and ${{ inputs.config-file }} (untrusted inputs) and are then used to construct values written to $env:GITHUB_OUTPUT (e.g., "health-json=$healthPath" >> $env:GITHUB_OUTPUT). No sanitization (printf '%s' | tr -d '\n\r') is applied before these writes, allowing newline injection into GITHUB_OUTPUT.

Locations:

- `action.yml:50`
- `action.yml:57`
- `action.yml:58`

### github-env-injection (severity: high)

In cli/action.yml, the variable $RESULTS is populated by running oss-health-scan with ${{ inputs.path }} and its output is written directly to $GITHUB_OUTPUT via a heredoc (`echo "$RESULTS" >> $GITHUB_OUTPUT`) without sanitization. Additionally, $AVG and $CRIT (derived from $RESULTS) are written to $GITHUB_OUTPUT without sanitization. An attacker-controlled package could produce output containing newlines that inject additional GITHUB_OUTPUT key-value pairs.

Locations:

- `cli/action.yml:55`
- `cli/action.yml:56`
- `cli/action.yml:57`
- `cli/action.yml:63`
- `cli/action.yml:64`

### unpinned-uses (severity: high)

cli/action.yml references `actions/setup-node@v4`, which uses a mutable tag instead of a full 40-character commit SHA. This is vulnerable to supply-chain attacks if the tag is moved to point to a different (potentially malicious) commit.

Locations:

- `cli/action.yml:36`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.evidence-dir }}" appears directly in run: block of step "Update All Evidence"; move to env: map

Locations:

- `action.yml:49`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.config-file }}" appears directly in run: block of step "Update All Evidence"; move to env: map

Locations:

- `action.yml:50`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, static-inline-injection, github-env-injection, unpinned-uses

**Notes:**

Fixed all 7 findings across action.yml and cli/action.yml:

1. action.yml script-injection/static-inline-injection: Moved ${{ inputs.evidence-dir }} and ${{ inputs.config-file }} to env: block as INPUT_EVIDENCE_DIR and INPUT_CONFIG_FILE; PowerShell script reads them via $env:INPUT_EVIDENCE_DIR and $env:INPUT_CONFIG_FILE.

2. action.yml github-env-injection: Added PowerShell newline sanitization ($healthPath -replace '[\r\n]', '') on path values before writing to $env:GITHUB_OUTPUT. Numeric values ($critical, $avg) are computed from parsed JSON and cannot contain newlines.

3. cli/action.yml script-injection: Moved ${{ inputs.include-dev }}, ${{ inputs.threshold }}, and ${{ inputs.path }} to env: block as INPUT_INCLUDE_DEV, INPUT_THRESHOLD, INPUT_PATH. All shell references updated to use env vars. inputs.path is a single path value (not a list), so "$INPUT_PATH" is correct.

4. cli/action.yml github-env-injection: Added tr -d '\n\r' sanitization for AVG and CRIT before writing to $GITHUB_OUTPUT. RESULTS heredoc write is preserved (heredoc is the correct multi-line output mechanism).

5. cli/action.yml unpinned-uses: Pinned actions/setup-node@v4 to full SHA 49933ea5288caeca8642d1e84afbd3f7d6820020 with # v4 comment.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in hardened/action/cli/action.yml by converting the FLAGS string variable to a bash array. Changed FLAGS="" to FLAGS=(), used FLAGS+=(--dev) and FLAGS+=(--threshold "$INPUT_THRESHOLD") to build the array with properly quoted elements, and replaced unquoted $FLAGS expansions with "${FLAGS[@]}" in both oss-health-scan invocations. This prevents shell metacharacter injection from user-controlled inputs.threshold and inputs.include-dev while correctly preserving argument boundaries.

