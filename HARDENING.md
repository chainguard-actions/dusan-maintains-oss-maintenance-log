<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log/v1.2.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **dusan-maintains--oss-maintenance-log/v1.2.0** was hardened automatically. 5 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Direct ${{ inputs.* }} expression interpolation inside run: blocks. In action.yml, `${{ inputs.evidence-dir }}` and `${{ inputs.config-file }}` are interpolated directly into a PowerShell run: block (sub-rule a). An attacker-controlled input value is substituted into the shell command string before the shell parses it, enabling command injection.

Locations:

- `action.yml:46`
- `action.yml:47`

### script-injection (severity: high)

Direct ${{ inputs.* }} expression interpolation inside bash run: blocks in cli/action.yml (sub-rule a and b). Offending lines include: `if [ "${{ inputs.include-dev }}" = "true" ]`, `FLAGS="$FLAGS --threshold ${{ inputs.threshold }}"`, `RESULTS=$(oss-health-scan ${{ inputs.path }} --json $FLAGS ...)` (also unquoted — sub-rule b), `oss-health-scan ${{ inputs.path }} $FLAGS --ci` (unquoted), `if [ "${{ inputs.threshold }}" != "0" ]`, and `echo "::error::$CRIT package(s) scored below threshold ${{ inputs.threshold }}"`. An attacker-controlled input value is substituted into the shell command string before the shell parses it, enabling command injection.

Locations:

- `cli/action.yml:51`
- `cli/action.yml:53`
- `cli/action.yml:57`
- `cli/action.yml:70`
- `cli/action.yml:73`
- `cli/action.yml:75`

### unpinned-uses (severity: high)

cli/action.yml uses `actions/setup-node@v4` — a mutable tag reference rather than a full 40-character commit SHA. This means the action could be silently updated to a different (potentially malicious) version without any change to the workflow file.

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

**Fixes applied:** script-injection, static-inline-injection, unpinned-uses

**Notes:**

Fixed three categories of findings across two files:

1. action.yml (script-injection / static-inline-injection): Moved `${{ inputs.evidence-dir }}` and `${{ inputs.config-file }}` out of the PowerShell run: block into the step's env: block as EVIDENCE_DIR and CONFIG_FILE. The script now reads `$env:EVIDENCE_DIR` and `$env:CONFIG_FILE` instead of interpolating expressions directly.

2. cli/action.yml (script-injection): Moved `${{ inputs.include-dev }}`, `${{ inputs.threshold }}`, and `${{ inputs.path }}` out of the bash run: block into the step's env: block as INPUT_INCLUDE_DEV, INPUT_THRESHOLD, and INPUT_PATH. All six offending lines now reference plain environment variables, eliminating the injection surface.

3. cli/action.yml (unpinned-uses): Pinned `actions/setup-node@v4` to the full commit SHA `49933ea5288caeca8642d1e84afbd3f7d6820020` with a `# v4` comment preserved for readability.

### Iteration 2

**Fixes applied:** github-env-injection, script-injection

**Notes:**

1. action.yml (github-env-injection): Added PowerShell sanitization (`-replace "`r|`n", ""`) to strip newlines/carriage returns from `$healthPath` and `$manifestPath` before writing to `$GITHUB_OUTPUT`, preventing newline injection from the caller-controlled `inputs.evidence-dir`. 2. cli/action.yml (script-injection): Converted `$FLAGS` from a plain string to a bash array (`FLAGS=()`). Flags are appended with `FLAGS+=(--dev)` and `FLAGS+=(--threshold "$INPUT_THRESHOLD")` (with `$INPUT_THRESHOLD` double-quoted), and expanded as `"${FLAGS[@]}"` in both `oss-health-scan` invocations, preventing word-splitting and shell metacharacter injection from `inputs.threshold`.

