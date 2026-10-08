<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log/v1.7.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log/v1.7.0** was hardened automatically. 9 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ }} expressions are directly interpolated inside run: shell commands in action.yml. The expressions `${{ github.action_path }}` (line 49), `${{ github.workspace }}` (lines 47, 50), `${{ inputs.evidence-dir }}` (line 52), `${{ inputs.config-file }}` (line 53), and `${{ inputs.compute-health-scores }}` (line 68) are all substituted by the Actions runner before the shell sees the script, allowing an attacker-controlled value to inject arbitrary shell commands.

Locations:

- `action.yml:49`
- `action.yml:50`
- `action.yml:52`
- `action.yml:53`
- `action.yml:68`

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ }} expressions are directly interpolated inside run: shell commands in cli/action.yml. The expressions `${{ inputs.include-dev }}` (line 54), `${{ inputs.threshold }}` (lines 57, 58), and `${{ inputs.path }}` (lines 62, 72) are substituted before the shell executes the script. An attacker controlling `inputs.path` or `inputs.threshold` can inject arbitrary shell commands (e.g., via `; malicious-command`).

Locations:

- `cli/action.yml:54`
- `cli/action.yml:57`
- `cli/action.yml:58`
- `cli/action.yml:62`
- `cli/action.yml:72`

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ }} expressions are directly interpolated inside run: shell commands in scan-action/action.yml. The expressions `${{ github.event.pull_request.number }}` (line 52), `${{ github.repository }}` (line 53), and `${{ steps.scan.outputs.critical }}` (lines 63, 64) are substituted before the shell executes the script. `github.event.pull_request.number` is attacker-controlled via PR title/metadata, and `steps.scan.outputs.critical` flows from tool output.

Locations:

- `scan-action/action.yml:52`
- `scan-action/action.yml:53`
- `scan-action/action.yml:63`
- `scan-action/action.yml:64`

### github-env-injection (severity: high)

In action.yml, the untrusted input `${{ inputs.evidence-dir }}` is interpolated directly into the run: block as `$evidenceDirInput`, which is then used to construct `$dir`, `$healthPath`, and `$manifestPath`. These derived values are written to `$GITHUB_OUTPUT` (e.g., `"health-json=$healthPath" >> $env:GITHUB_OUTPUT`) without any sanitization step (`printf '%s' ... | tr -d '\n\r'`). A newline in `inputs.evidence-dir` could inject arbitrary key=value pairs into GITHUB_OUTPUT.

Locations:

- `action.yml:52`
- `action.yml:78`
- `action.yml:79`

### github-env-injection (severity: high)

In cli/action.yml, `${{ inputs.path }}` is directly interpolated into the oss-health-scan command (line 62), and the resulting `$RESULTS` (which may contain newlines from tool output) is written to `$GITHUB_OUTPUT` via `echo "$RESULTS" >> $GITHUB_OUTPUT` (line 64) without sanitization. Additionally, `${{ inputs.threshold }}` flows into `FLAGS` and into the command. An attacker-controlled `inputs.path` value containing newlines could inject arbitrary entries into GITHUB_OUTPUT.

Locations:

- `cli/action.yml:62`
- `cli/action.yml:64`

### unpinned-uses (severity: high)

Both cli/action.yml and scan-action/action.yml reference `actions/setup-node@v4` using a mutable version tag instead of a pinned 40-character commit SHA. If the `v4` tag is moved to a different commit (e.g., via a supply-chain attack), the action will silently execute untrusted code.

Locations:

- `cli/action.yml:40`
- `scan-action/action.yml:31`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.evidence-dir }}" appears directly in run: block of step "Update All Evidence"; move to env: map

Locations:

- `action.yml:53`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.config-file }}" appears directly in run: block of step "Update All Evidence"; move to env: map

Locations:

- `action.yml:54`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.compute-health-scores }}" appears directly in run: block of step "Update All Evidence"; move to env: map

Locations:

- `action.yml:75`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, static-inline-injection

**Notes:**

Fixed all findings across three files:

**action.yml**: Moved all ${{ }} expressions (github.action_path, github.workspace, inputs.evidence-dir, inputs.config-file, inputs.compute-health-scores) to the env: block. PowerShell script now reads them via $env:VAR_NAME. Added sanitization for paths written to $GITHUB_OUTPUT using PowerShell's -replace operator to strip newlines/carriage returns.

**cli/action.yml**: Moved all ${{ }} expressions (inputs.include-dev, inputs.threshold, inputs.path) to the env: block. Bash script reads them via $INPUT_INCLUDE_DEV, $INPUT_THRESHOLD, $INPUT_PATH. Added sanitization for AVG and CRIT values before writing to $GITHUB_OUTPUT using printf + tr -d '\n\r'. Pinned actions/setup-node@v4 to full SHA @49933ea5288caeca8642d1e84afbd3f7d6820020.

**scan-action/action.yml**: Moved ${{ github.event.pull_request.number }}, ${{ github.repository }}, and ${{ steps.scan.outputs.critical }} to env: blocks. Added sanitization for crit value before writing to $GITHUB_OUTPUT. Sanitized PR_NUMBER and REPO before using in gh commands. Pinned actions/setup-node@v4 to full SHA @49933ea5288caeca8642d1e84afbd3f7d6820020.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in cli/action.yml 'Run health scan' step:
1. Sanitized INPUT_THRESHOLD by stripping non-digit characters with `tr -cd '0-9'`, storing result in SAFE_THRESHOLD.
2. Converted FLAGS from a string variable to a bash array, adding each flag/value as separate elements (FLAGS+=(...)).
3. Replaced all unquoted `$FLAGS` expansions with properly quoted `"${FLAGS[@]}"` array expansions.
4. Updated threshold condition checks and error messages to use SAFE_THRESHOLD instead of INPUT_THRESHOLD.
This prevents shell metacharacter injection via the `threshold` input while preserving correct argument passing behavior.

