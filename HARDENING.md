<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log/v1.2.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log/v1.2.0** was hardened automatically. 7 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a) violation: ${{ inputs.evidence-dir }} and ${{ inputs.config-file }} are directly interpolated into the PowerShell run: block. An attacker-controlled caller can inject arbitrary PowerShell commands via these inputs. Offending lines: `$dir = "${{ inputs.evidence-dir }}"` and `$cfg = "${{ inputs.config-file }}"`.

Locations:

- `action.yml:47`
- `action.yml:48`

### script-injection (severity: high)

Rule (a) violation: Multiple ${{ inputs.* }} expressions are directly interpolated into the bash run: block in cli/action.yml. Specifically: `${{ inputs.include-dev }}` (line 52), `${{ inputs.threshold }}` (lines 55, 56, 75, 76), and `${{ inputs.path }}` (lines 59, 72) are all interpolated directly into shell commands, allowing an attacker-controlled caller to inject arbitrary shell commands.

Locations:

- `cli/action.yml:52`
- `cli/action.yml:55`
- `cli/action.yml:56`
- `cli/action.yml:59`
- `cli/action.yml:72`
- `cli/action.yml:75`
- `cli/action.yml:76`

### github-env-injection (severity: high)

In action.yml, ${{ inputs.evidence-dir }} is interpolated into the PowerShell variable $dir without sanitization, and $dir is then used to construct values written to $env:GITHUB_OUTPUT (e.g., `"health-json=$healthPath" >> $env:GITHUB_OUTPUT`). A newline injected via inputs.evidence-dir could poison GITHUB_OUTPUT with attacker-controlled key-value pairs. Similarly ${{ inputs.config-file }} flows into $cfg. No `printf '%s' ... | tr -d '\n\r'` sanitization is applied before the writes.

Locations:

- `action.yml:47`
- `action.yml:48`
- `action.yml:55`
- `action.yml:56`

### github-env-injection (severity: high)

In cli/action.yml, ${{ inputs.threshold }} is directly interpolated and its value is echoed into $GITHUB_OUTPUT (e.g., `echo "::error::$CRIT package(s) scored below threshold ${{ inputs.threshold }}"`). Additionally, $RESULTS (derived from running oss-health-scan with unsanitized ${{ inputs.path }}) is written to $GITHUB_OUTPUT via a heredoc without sanitization. No `printf '%s' ... | tr -d '\n\r'` sanitization is applied before any of these writes.

Locations:

- `cli/action.yml:59`
- `cli/action.yml:61`
- `cli/action.yml:76`

### unpinned-uses (severity: high)

cli/action.yml references `actions/setup-node@v4`, which is a mutable tag reference rather than a pinned 40-character commit SHA. This is vulnerable to supply-chain attacks if the tag is moved to a different commit.

Locations:

- `cli/action.yml:38`

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

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, static-inline-injection

**Notes:**

Fixed all 7 findings across action.yml and cli/action.yml:

1. action.yml (script-injection + static-inline-injection + github-env-injection): Moved ${{ inputs.evidence-dir }} and ${{ inputs.config-file }} from inline PowerShell interpolation into the env: block as INPUT_EVIDENCE_DIR and INPUT_CONFIG_FILE. Added PowerShell -replace '[\r\n]', '' sanitization on both values and on the derived paths before writing to $env:GITHUB_OUTPUT.

2. cli/action.yml (script-injection + github-env-injection): Moved ${{ inputs.include-dev }}, ${{ inputs.threshold }}, and ${{ inputs.path }} from inline bash interpolation into the env: block as INPUT_INCLUDE_DEV, INPUT_THRESHOLD, and INPUT_PATH. Added printf '%s' ... | tr -d '\n\r' sanitization on threshold and path before use in GITHUB_OUTPUT writes and shell commands.

3. cli/action.yml (unpinned-uses): Pinned actions/setup-node@v4 to full commit SHA 49933ea5288caeca8642d1e84afbd3f7d6820020 with # v4 comment.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Converted the FLAGS variable from a space-concatenated string to a bash array in hardened/action/cli/action.yml. The two unquoted $FLAGS expansions (lines 71 and 80) were replaced with "${FLAGS[@]}" array expansions. Array elements are built with FLAGS+=(--dev) and FLAGS+=(--threshold "$SAFE_THRESHOLD"), ensuring each flag token is a separate properly-quoted argument and preventing shell metacharacter injection from attacker-controlled inputs.

