<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log/v1.3.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log/v1.3.0** was hardened automatically. 7 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Multiple ${{ inputs.* }} expressions are directly interpolated inside run: shell commands in cli/action.yml. Specifically: `${{ inputs.include-dev }}` is used in a string comparison; `${{ inputs.threshold }}` is appended to FLAGS and used in comparisons; `${{ inputs.path }}` is passed unquoted directly to the oss-health-scan command. An attacker controlling these inputs can inject arbitrary shell commands (e.g. via semicolons, backticks, or $(...) in inputs.path or inputs.threshold).

Locations:

- `cli/action.yml:52`
- `cli/action.yml:54`
- `cli/action.yml:55`
- `cli/action.yml:58`
- `cli/action.yml:66`
- `cli/action.yml:68`
- `cli/action.yml:72`

### script-injection (severity: high)

Rule (a): In action.yml, `${{ inputs.evidence-dir }}` and `${{ inputs.config-file }}` are directly interpolated inside a PowerShell run: block (assigned to $dir and $cfg). An attacker-controlled input value can inject arbitrary PowerShell commands through these interpolations.

Locations:

- `action.yml:47`
- `action.yml:48`

### github-env-injection (severity: high)

In action.yml, the inputs ${{ inputs.evidence-dir }} and ${{ inputs.config-file }} are interpolated into PowerShell variables $dir and $cfg, which are then used to construct paths written to $env:GITHUB_OUTPUT (e.g. `"health-json=$healthPath" >> $env:GITHUB_OUTPUT`). No sanitization (printf '%s' ... | tr -d '\n\r') is applied before writing to the special environment file, allowing newline injection to poison GITHUB_OUTPUT.

Locations:

- `action.yml:47`
- `action.yml:48`
- `action.yml:53`
- `action.yml:54`

### github-env-injection (severity: high)

In cli/action.yml, the RESULTS variable (derived from running oss-health-scan with ${{ inputs.path }}) is written directly to $GITHUB_OUTPUT via a heredoc (`echo "$RESULTS" >> $GITHUB_OUTPUT`) without sanitization. Additionally, AVG and CRIT values derived from RESULTS are written to $GITHUB_OUTPUT without sanitization. No `printf '%s' ... | tr -d '\n\r'` step is applied before any of these writes.

Locations:

- `cli/action.yml:60`
- `cli/action.yml:61`
- `cli/action.yml:62`
- `cli/action.yml:70`
- `cli/action.yml:71`

### unpinned-uses (severity: high)

cli/action.yml references `actions/setup-node@v4`, which is a mutable tag reference rather than a pinned 40-character commit SHA. This is vulnerable to supply-chain attacks if the tag is moved to point to a different (potentially malicious) commit.

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

1. **unpinned-uses** (cli/action.yml): Pinned `actions/setup-node@v4` → `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4`.

2. **script-injection** (cli/action.yml): Moved `${{ inputs.include-dev }}`, `${{ inputs.threshold }}`, and `${{ inputs.path }}` into the step's `env:` block as `INPUT_INCLUDE_DEV`, `INPUT_THRESHOLD`, `INPUT_PATH`. Shell script now references these env vars instead of inline expressions.

3. **script-injection / static-inline-injection** (action.yml): Moved `${{ inputs.evidence-dir }}` and `${{ inputs.config-file }}` into the step's `env:` block as `INPUT_EVIDENCE_DIR` and `INPUT_CONFIG_FILE`. PowerShell script reads `$env:INPUT_EVIDENCE_DIR` and `$env:INPUT_CONFIG_FILE` with immediate newline stripping via `-replace '[\r\n]', ''`.

4. **github-env-injection** (action.yml): Path values written to `$env:GITHUB_OUTPUT` are sanitized with `-replace '[\r\n]', ''` before writing.

5. **github-env-injection** (cli/action.yml): `AVG` and `CRIT` values are sanitized with `printf '%s' "$VAR" | tr -d '\n\r'` before writing to `$GITHUB_OUTPUT`. `RESULTS` is written using a heredoc (`results<<EOF`) which is the correct multiline approach.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in hardened/action/cli/action.yml by converting the FLAGS string variable to a bash array. Changed `FLAGS=""` to `FLAGS=()`, `FLAGS="$FLAGS --dev"` to `FLAGS+=(--dev)`, and `FLAGS="$FLAGS --threshold $INPUT_THRESHOLD"` to `FLAGS+=(--threshold "$INPUT_THRESHOLD")`. Updated both unquoted `$FLAGS` expansions (lines 68 and 82) to `"${FLAGS[@]}"`. This ensures the threshold value is always treated as a single quoted argument and cannot inject shell metacharacters.

