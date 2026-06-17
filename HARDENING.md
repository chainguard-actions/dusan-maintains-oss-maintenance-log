<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log/v1.3.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **dusan-maintains--oss-maintenance-log/v1.3.0** was hardened automatically. 7 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Direct expression interpolation of inputs in run: blocks. In action.yml, `${{ inputs.evidence-dir }}` and `${{ inputs.config-file }}` are interpolated directly into a PowerShell run: block, allowing an attacker to inject arbitrary PowerShell commands via those inputs. Example offending lines: `$dir = "${{ inputs.evidence-dir }}"` and `$cfg = "${{ inputs.config-file }}"`.

Locations:

- `action.yml:48`
- `action.yml:49`

### script-injection (severity: high)

Rule (a): Direct expression interpolation of inputs in run: blocks. In cli/action.yml, `${{ inputs.include-dev }}`, `${{ inputs.threshold }}`, and `${{ inputs.path }}` are interpolated directly into bash run: blocks. `${{ inputs.path }}` is also used unquoted (rule b) in shell commands like `oss-health-scan ${{ inputs.path }} --json $FLAGS` and `oss-health-scan ${{ inputs.path }} $FLAGS --ci`, enabling command injection. Offending lines include: `if [ "${{ inputs.include-dev }}" = "true" ]`, `FLAGS="$FLAGS --threshold ${{ inputs.threshold }}"`, `RESULTS=$(oss-health-scan ${{ inputs.path }} --json $FLAGS ...)`, `oss-health-scan ${{ inputs.path }} $FLAGS --ci`, and `if [ "${{ inputs.threshold }}" != "0" ]`.

Locations:

- `cli/action.yml:36`
- `cli/action.yml:39`
- `cli/action.yml:43`
- `cli/action.yml:56`
- `cli/action.yml:60`
- `cli/action.yml:63`

### github-env-injection (severity: high)

In action.yml, the inputs `inputs.evidence-dir` and `inputs.config-file` are interpolated directly into the PowerShell run: block and the computed paths are then written to $env:GITHUB_OUTPUT without any newline sanitization (no `printf '%s' ... | tr -d '\n\r'` step). An attacker-controlled newline in these inputs could inject arbitrary key=value pairs into GITHUB_OUTPUT.

Locations:

- `action.yml:48`
- `action.yml:49`

### github-env-injection (severity: high)

In cli/action.yml, the inputs `inputs.threshold` and `inputs.path` are interpolated directly into the bash run: block and their derived values (AVG, CRIT) are written to $GITHUB_OUTPUT without sanitization. Additionally, `echo "average=$AVG" >> $GITHUB_OUTPUT` and `echo "critical=$CRIT" >> $GITHUB_OUTPUT` write values derived from unsanitized input-controlled data without the required `printf '%s' ... | tr -d '\n\r'` sanitization step.

Locations:

- `cli/action.yml:50`
- `cli/action.yml:51`
- `cli/action.yml:52`

### unpinned-uses (severity: high)

cli/action.yml references `actions/setup-node@v4`, which is a mutable tag reference rather than a pinned full 40-character commit SHA. This is vulnerable to supply-chain attacks if the tag is moved to a different commit. It should be pinned to a specific SHA, e.g. `actions/setup-node@1d0ff469b12462b0f186a6e9b93e3d5d8e5e4e5e # v4`.

Locations:

- `cli/action.yml:28`

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

Fixed all findings across action.yml and cli/action.yml:

1. action.yml - script-injection & static-inline-injection: Moved `inputs.evidence-dir` and `inputs.config-file` out of the PowerShell run block into env vars (`INPUT_EVIDENCE_DIR`, `INPUT_CONFIG_FILE`), accessed via `$env:INPUT_EVIDENCE_DIR` and `$env:INPUT_CONFIG_FILE`.

2. action.yml - github-env-injection: Added PowerShell `-replace '[\r\n]', ''` sanitization on computed path values before writing to `$env:GITHUB_OUTPUT`.

3. cli/action.yml - script-injection: Moved `inputs.include-dev`, `inputs.threshold`, and `inputs.path` to env vars (`INPUT_INCLUDE_DEV`, `INPUT_THRESHOLD`, `INPUT_PATH`). Replaced all `${{ inputs.* }}` interpolations in the run block with env var references. Quoted `"$INPUT_PATH"` in oss-health-scan invocations.

4. cli/action.yml - github-env-injection: Added `printf '%s' "$AVG" | tr -d '\n\r'` and `printf '%s' "$CRIT" | tr -d '\n\r'` sanitization before writing outputs to `$GITHUB_OUTPUT`.

5. cli/action.yml - unpinned-uses: Pinned `actions/setup-node@v4` to full SHA `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4`.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in cli/action.yml by converting FLAGS from a plain string to a bash array. FLAGS=() is initialized as an array, elements are added with FLAGS+=("--dev") and FLAGS+=("--threshold" "$INPUT_THRESHOLD"), and both usages (line 68 JSON scan and line 84 human-readable report) now expand with "${FLAGS[@]}" instead of the unquoted $FLAGS. This prevents shell metacharacter injection from attacker-controlled threshold or include-dev inputs.

