<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log--cli/v1.7.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log--cli/v1.7.0** was hardened automatically. 10 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Run health scan' step directly interpolates multiple ${{ inputs.* }} expressions inside the run: shell script without routing them through env: variables first. Specifically: (a) `${{ inputs.include-dev }}` is interpolated into a shell `if` condition; (b) `${{ inputs.threshold }}` is interpolated into shell `if` conditions and an `echo` statement; (c) `${{ inputs.path }}` is interpolated directly into shell command arguments (e.g., `oss-health-scan ${{ inputs.path }} --json $FLAGS`). An attacker controlling these inputs can inject arbitrary shell commands. All three must be moved to env: variables and those variables must be double-quoted in the shell script.

Locations:

- `action.yml:52`

### github-env-injection (severity: high)

The 'Run health scan' step writes $RESULTS to $GITHUB_OUTPUT via a heredoc (`echo "results<<EOF" >> $GITHUB_OUTPUT; echo "$RESULTS" >> $GITHUB_OUTPUT`) without sanitization. $RESULTS is derived from running `oss-health-scan ${{ inputs.path }} ...`, making it attacker-influenced. A malicious package name or tool output containing newlines could inject additional key=value pairs into GITHUB_OUTPUT. The required sanitization step (`printf '%s' "$RESULTS" | tr -d '\n\r'`) is absent before the write.

Locations:

- `action.yml:58`

### unpinned-uses (severity: high)

The composite action uses `actions/setup-node@v4`, which is pinned to a mutable tag (`@v4`) rather than an immutable 40-character commit SHA. If the tag is moved (e.g., by a supply-chain compromise of the actions/setup-node repository), the action will silently execute different code. It should be pinned to a full SHA, e.g., `actions/setup-node@1d0ff469b12462b0e4b0b3e4e0c8b5b0e0b0e0b0 # v4`.

Locations:

- `action.yml:44`

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
1. Pinned actions/setup-node@v4 to full SHA @49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.
2. Moved all ${{ inputs.include-dev }}, ${{ inputs.threshold }}, and ${{ inputs.path }} expressions to the env: block as INPUT_INCLUDE_DEV, INPUT_THRESHOLD, and INPUT_PATH respectively. All references in the shell script use double-quoted $INPUT_* variables.
3. Sanitized $RESULTS before writing to $GITHUB_OUTPUT using `safe_results=$(printf '%s' "$RESULTS" | tr -d '\n\r')` and writing $safe_results instead of raw $RESULTS in the heredoc.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection vulnerability in action.yml by converting the FLAGS string variable to a bash array. Changes made: (1) Changed `FLAGS=""` to `FLAGS=()`, (2) Changed `FLAGS="$FLAGS --dev"` to `FLAGS+=(--dev)`, (3) Changed `FLAGS="$FLAGS --threshold $INPUT_THRESHOLD"` to `FLAGS+=(--threshold "$INPUT_THRESHOLD")` — this properly quotes the user-controlled threshold value, (4) Changed both unquoted `$FLAGS` expansions to `"${FLAGS[@]}"` — this ensures each flag is passed as a separate argument with proper quoting, preventing shell metacharacter injection. The step uses `shell: bash` so bash arrays are appropriate.

