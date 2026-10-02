<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log--cli/v1.6.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log--cli/v1.6.0** was hardened automatically. 10 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a) violation: Multiple `${{ inputs.* }}` expressions are directly interpolated inside `run:` shell command strings in the 'Run health scan' step. An attacker who controls these inputs can inject arbitrary shell commands. Offending lines include:
- `if [ "${{ inputs.include-dev }}" = "true" ]` — inputs.include-dev interpolated directly into shell
- `if [ "${{ inputs.threshold }}" != "0" ]` — inputs.threshold interpolated directly into shell (appears 3 times)
- `FLAGS="$FLAGS --threshold ${{ inputs.threshold }}"` — inputs.threshold in unquoted flag construction
- `RESULTS=$(oss-health-scan ${{ inputs.path }} --json $FLAGS ...)` — inputs.path interpolated unquoted into command substitution
- `oss-health-scan ${{ inputs.path }} $FLAGS --ci` — inputs.path interpolated unquoted again
All `${{ inputs.* }}` values must be passed via `env:` variables and then double-quoted in the shell script.

Locations:

- `action.yml:58`
- `action.yml:61`
- `action.yml:62`
- `action.yml:65`
- `action.yml:74`
- `action.yml:77`
- `action.yml:78`

### github-env-injection (severity: high)

The `$RESULTS` variable — produced by running `oss-health-scan ${{ inputs.path }} --json $FLAGS` where `inputs.path` is attacker-controlled — is written to `$GITHUB_OUTPUT` via a heredoc (`echo "$RESULTS" >> $GITHUB_OUTPUT`) without any sanitization (`printf '%s' ... | tr -d '\n\r'`). A malicious `inputs.path` value could inject newlines into `$GITHUB_OUTPUT`, allowing an attacker to set arbitrary output variables or environment values. Similarly, `echo "average=$AVG" >> $GITHUB_OUTPUT` and `echo "critical=$CRIT" >> $GITHUB_OUTPUT` write unsanitized values derived from attacker-influenced tool output.

Locations:

- `action.yml:67`
- `action.yml:71`
- `action.yml:72`

### unpinned-uses (severity: high)

The composite action uses `actions/setup-node@v4`, which is pinned to a mutable tag (`v4`) rather than an immutable 40-character commit SHA. If the tag is moved (e.g., by a supply-chain compromise of the actions/setup-node repository), the action will silently execute different code. It should be pinned to a full SHA, e.g. `actions/setup-node@1d0ff469b12f8a2e8a3c6e5f3e8b7c9d0a2f4e6a # v4`.

Locations:

- `action.yml:42`

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

**Fixes applied:** unpinned-uses, script-injection, static-inline-injection, github-env-injection

**Notes:**

Fixed all findings in action.yml:
1. Pinned actions/setup-node@v4 to full SHA @49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
2. Moved all ${{ inputs.include-dev }}, ${{ inputs.threshold }}, and ${{ inputs.path }} expressions out of the run: shell script into the step's env: block as INPUT_INCLUDE_DEV, INPUT_THRESHOLD, and INPUT_PATH respectively. All shell references now use properly double-quoted environment variables.
3. Sanitized values written to $GITHUB_OUTPUT: AVG and CRIT are passed through 'printf | tr -d \n\r' before being written as safe_avg and safe_crit. The results heredoc uses printf '%s\n' for proper output. $GITHUB_OUTPUT is now quoted throughout.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in the 'Run health scan' step by converting the FLAGS string variable to a bash array. Previously, INPUT_THRESHOLD (user-controlled) was appended to a string FLAGS without quoting, and FLAGS was then expanded unquoted in two shell commands, allowing shell metacharacter injection. The fix: (1) changed `FLAGS=""` to `FLAGS=()`, (2) changed string concatenation to array appends with `FLAGS+=(--dev)` and `FLAGS+=(--threshold "$INPUT_THRESHOLD")` (now properly double-quoted), and (3) changed both unquoted `$FLAGS` expansions to `"${FLAGS[@]}"` so each array element is properly quoted when the commands execute.

