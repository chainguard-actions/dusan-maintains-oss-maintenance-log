<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log--cli/v1.3.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log--cli/v1.3.0** was hardened automatically. 10 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

The composite action uses `actions/setup-node@v4`, which is pinned to a mutable version tag rather than an immutable 40-character commit SHA. This means the action could be silently updated (or compromised) without the consuming workflow noticing. It should be pinned to a full SHA, e.g. `actions/setup-node@1d0ff469b12462b0e4b4c8b33c0a3b1d7b0b7b0b # v4`.

Locations:

- `action.yml:40`

### script-injection (severity: high)

Rule (a) violation: Multiple `${{ inputs.* }}` expressions are interpolated directly inside `run:` shell command strings, enabling script injection. An attacker who controls these inputs can inject arbitrary shell commands.

- Line 48: `if [ "${{ inputs.include-dev }}" = "true" ]` — inputs.include-dev interpolated directly into shell
- Line 51: `if [ "${{ inputs.threshold }}" != "0" ]` — inputs.threshold interpolated directly into shell
- Line 52: `FLAGS="$FLAGS --threshold ${{ inputs.threshold }}"` — inputs.threshold interpolated directly into shell
- Line 55: `RESULTS=$(oss-health-scan ${{ inputs.path }} --json $FLAGS ...)` — inputs.path interpolated directly into shell command
- Line 65: `oss-health-scan ${{ inputs.path }} $FLAGS --ci` — inputs.path interpolated directly into shell
- Line 68: `if [ "${{ inputs.threshold }}" != "0" ]` — inputs.threshold interpolated directly into shell
- Line 70: `echo "::error::$CRIT package(s) scored below threshold ${{ inputs.threshold }}"` — inputs.threshold interpolated directly into shell

All these inputs should be moved to `env:` variables and referenced as quoted shell variables (e.g. `"$INPUT_PATH"`) instead.

Locations:

- `action.yml:48`
- `action.yml:51`
- `action.yml:52`
- `action.yml:55`
- `action.yml:65`
- `action.yml:68`
- `action.yml:70`

### github-env-injection (severity: high)

The `run:` block writes `$RESULTS`, `$AVG`, and `$CRIT` to `$GITHUB_OUTPUT` without sanitization (no `printf '%s' ... | tr -d '\n\r'` step). `$RESULTS` is the raw JSON output of `oss-health-scan` invoked with the untrusted `${{ inputs.path }}` argument, making it an untrusted value. Writing unsanitized multi-line content to `$GITHUB_OUTPUT` via `echo` allows newline injection that can forge additional output variables. The heredoc pattern used for `$RESULTS` (`echo "results<<EOF"`) is particularly dangerous as injected newlines in the content could break out of the heredoc boundary. Each write should be preceded by sanitization: `safe=$(printf '%s' "$VAR" | tr -d '\n\r')`.

Locations:

- `action.yml:56`
- `action.yml:57`
- `action.yml:58`
- `action.yml:62`
- `action.yml:63`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.include-dev }}" appears directly in run: block of step "Run health scan"; move to env: map

Locations:

- `action.yml:57`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.threshold }}" appears directly in run: block of step "Run health scan"; move to env: map

Locations:

- `action.yml:60`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.threshold }}" appears directly in run: block of step "Run health scan"; move to env: map

Locations:

- `action.yml:61`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.path }}" appears directly in run: block of step "Run health scan"; move to env: map

Locations:

- `action.yml:65`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.path }}" appears directly in run: block of step "Run health scan"; move to env: map

Locations:

- `action.yml:77`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.threshold }}" appears directly in run: block of step "Run health scan"; move to env: map

Locations:

- `action.yml:80`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.threshold }}" appears directly in run: block of step "Run health scan"; move to env: map

Locations:

- `action.yml:81`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all findings in hardened/action/action.yml:
1. unpinned-uses: Pinned actions/setup-node@v4 to full SHA 49933ea5288caeca8642d1e84afbd3f7d6820020 with # v4 comment.
2. script-injection / static-inline-injection: Moved all ${{ inputs.path }}, ${{ inputs.threshold }}, and ${{ inputs.include-dev }} expressions from the run: shell block into the step's env: block as INPUT_PATH, INPUT_THRESHOLD, and INPUT_INCLUDE_DEV. All shell references now use safe $INPUT_* variables with proper quoting.
3. github-env-injection: Replaced the dangerous heredoc pattern for RESULTS with a sanitized single-line write. All three output values (results, average, critical) are now sanitized with printf '%s' "$VAR" | tr -d '\n\r' before being written to $GITHUB_OUTPUT.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Converted FLAGS from a string variable to a bash array in the 'Run health scan' step of action.yml. Replaced `FLAGS=""` with `FLAGS=()`, flag assignments with `FLAGS+=(--dev)` and `FLAGS+=(--threshold "$INPUT_THRESHOLD")`, and both unquoted `$FLAGS` expansions with `"${FLAGS[@]}"`. This eliminates word splitting and glob expansion on attacker-controlled input values while correctly passing each flag as a separate argument to the oss-health-scan command.

