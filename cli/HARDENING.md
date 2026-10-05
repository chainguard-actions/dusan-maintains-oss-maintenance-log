<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log--cli/v1.2.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log--cli/v1.2.0** was hardened automatically. 10 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

action.yml uses actions/setup-node@v4, which is a mutable tag reference rather than a pinned 40-character commit SHA. This is vulnerable to supply-chain attacks if the tag is moved to point to malicious code.

Locations:

- `action.yml:37`

### script-injection (severity: high)

The 'Run health scan' step directly interpolates multiple ${{ inputs.* }} expressions inside run: shell command strings (rule a). Specifically: (1) `if [ "${{ inputs.include-dev }}" = "true" ]` — inputs.include-dev is interpolated directly into a shell conditional; (2) `if [ "${{ inputs.threshold }}" != "0" ]` and `FLAGS="$FLAGS --threshold ${{ inputs.threshold }}"` — inputs.threshold is interpolated multiple times; (3) `RESULTS=$(oss-health-scan ${{ inputs.path }} --json $FLAGS ...)` — inputs.path is interpolated unquoted directly into a shell command; (4) `oss-health-scan ${{ inputs.path }} $FLAGS --ci` — inputs.path interpolated again unquoted; (5) `echo "::error::$CRIT package(s) scored below threshold ${{ inputs.threshold }}"` — inputs.threshold interpolated again. An attacker controlling these inputs can inject arbitrary shell commands.

Locations:

- `action.yml:49`

### github-env-injection (severity: high)

The 'Run health scan' step writes values derived from untrusted inputs to $GITHUB_OUTPUT without sanitization. Specifically: (1) `echo "$RESULTS" >> $GITHUB_OUTPUT` — $RESULTS is produced by running oss-health-scan with the unsanitized ${{ inputs.path }}, so its content is attacker-influenced and written without `tr -d '\n\r'` sanitization; (2) `echo "average=$AVG" >> $GITHUB_OUTPUT` and `echo "critical=$CRIT" >> $GITHUB_OUTPUT` — these values are derived from $RESULTS and written without sanitization. A newline in any of these values could inject additional key=value pairs into GITHUB_OUTPUT.

Locations:

- `action.yml:57`

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

1. Pinned actions/setup-node@v4 to full commit SHA 49933ea5288caeca8642d1e84afbd3f7d6820020. 2. Moved all ${{ inputs.include-dev }}, ${{ inputs.threshold }}, and ${{ inputs.path }} expressions out of the run: shell block and into the step's env: map as INPUT_INCLUDE_DEV, INPUT_THRESHOLD, and INPUT_PATH. All shell references now use plain $VAR_NAME syntax. inputs.path is now quoted as "$INPUT_PATH" to prevent word-splitting. 3. Sanitized AVG and CRIT values with `printf '%s' "$VAR" | tr -d '\n\r'` before writing to $GITHUB_OUTPUT to prevent newline injection. The multiline RESULTS output uses the heredoc EOF delimiter pattern which is the correct approach for multiline values.

### Iteration 2

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed script-injection by converting the string-based FLAGS variable to a bash array (FLAGS=()), using FLAGS+=(--dev) and FLAGS+=(--threshold "$INPUT_THRESHOLD") for safe element addition, and expanding with "${FLAGS[@]}" in both oss-health-scan invocations. Fixed github-env-injection by replacing the unsanitized "$RESULTS" in the heredoc output with "$safe_results" (which was already computed via printf '%s' "$RESULTS" | tr -d '\n\r' but was never actually used for the output).

