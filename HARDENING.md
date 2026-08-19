<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log/v1.6.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log/v1.6.0** was hardened automatically. 7 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple `${{ inputs.* }}` expressions are directly interpolated inside a `run:` shell block in action.yml. Specifically, `${{ inputs.evidence-dir }}` and `${{ inputs.config-file }}` are embedded directly in the PowerShell run script. An attacker-controlled input value could inject arbitrary PowerShell commands (e.g., via semicolons or newlines). These should be passed via `env:` variables and referenced as `$env:VAR_NAME` instead.

Locations:

- `action.yml:47`
- `action.yml:48`

### script-injection (severity: high)

Sub-rule (a): Multiple `${{ inputs.* }}` expressions are directly interpolated inside a `run:` bash block in cli/action.yml. Offending lines include: `if [ "${{ inputs.include-dev }}" = "true" ]`, `FLAGS="$FLAGS --threshold ${{ inputs.threshold }}"`, `RESULTS=$(oss-health-scan ${{ inputs.path }} --json $FLAGS ...)`, `oss-health-scan ${{ inputs.path }} $FLAGS --ci`, `if [ "${{ inputs.threshold }}" != "0" ]`, and `echo "::error::$CRIT package(s) scored below threshold ${{ inputs.threshold }}"`. The `inputs.path` value is also used unquoted (sub-rule b), allowing shell metacharacter injection. All these inputs should be moved to `env:` variables and properly double-quoted.

Locations:

- `cli/action.yml:57`
- `cli/action.yml:61`
- `cli/action.yml:64`
- `cli/action.yml:72`
- `cli/action.yml:75`
- `cli/action.yml:76`

### github-env-injection (severity: high)

In action.yml, `${{ inputs.evidence-dir }}` and `${{ inputs.config-file }}` are interpolated into PowerShell variables `$dir` and `$cfg`, which are then used to construct values written to `$env:GITHUB_OUTPUT` (e.g., `"health-json=$healthPath" >> $env:GITHUB_OUTPUT`). No sanitization step (printf/tr -d newlines) is applied before the write. A newline in the input could inject arbitrary key=value pairs into GITHUB_OUTPUT.

Locations:

- `action.yml:47`
- `action.yml:48`

### github-env-injection (severity: high)

In cli/action.yml, `$RESULTS` (produced by running `oss-health-scan ${{ inputs.path }} --json ...`) is written directly to `$GITHUB_OUTPUT` via `echo "$RESULTS" >> $GITHUB_OUTPUT` using a heredoc-style delimiter. The `inputs.path` value is attacker-controlled and injected unsanitized into the command that produces `$RESULTS`. No sanitization (printf '%s' | tr -d '\n\r') is applied before writing to GITHUB_OUTPUT.

Locations:

- `cli/action.yml:66`
- `cli/action.yml:67`

### unpinned-uses (severity: high)

cli/action.yml references `actions/setup-node@v4` using a mutable version tag instead of a pinned 40-character commit SHA. This is vulnerable to supply-chain attacks if the tag is moved to point to a different (potentially malicious) commit. It should be pinned to a full SHA, e.g., `actions/setup-node@1d0ff469b12294b4f0f8b0a8a666b4f6f7e4e4b2 # v4`.

Locations:

- `cli/action.yml:43`

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

1. action.yml - script-injection & static-inline-injection: Moved `${{ inputs.evidence-dir }}` and `${{ inputs.config-file }}` from inline run: interpolation to env: block (EVIDENCE_DIR, CONFIG_FILE). PowerShell now reads them via $env:EVIDENCE_DIR and $env:CONFIG_FILE.

2. action.yml - github-env-injection: Applied PowerShell `-replace '[\r\n]', ''` to sanitize $dir, $cfg, $healthPath, and $manifestPath before writing to $env:GITHUB_OUTPUT, preventing newline injection attacks.

3. cli/action.yml - script-injection: Moved `${{ inputs.include-dev }}`, `${{ inputs.threshold }}`, and `${{ inputs.path }}` to env: block as INPUT_INCLUDE_DEV, INPUT_THRESHOLD, INPUT_PATH. All shell references now use env vars with $INPUT_PATH properly double-quoted.

4. cli/action.yml - github-env-injection: Added `safe_results=$(printf '%s' "$RESULTS" | tr -d '\r')` to strip carriage returns before writing to GITHUB_OUTPUT via heredoc. Also quoted "$GITHUB_OUTPUT" throughout.

5. cli/action.yml - unpinned-uses: Pinned `actions/setup-node@v4` to full commit SHA `49933ea5288caeca8642d1e84afbd3f7d6820020` with `# v4` comment.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Replaced the FLAGS string variable with a bash array in cli/action.yml 'Run health scan' step. Previously, FLAGS was built as a plain string and expanded unquoted ($FLAGS), allowing word-splitting and glob expansion on attacker-controlled inputs.threshold and inputs.include-dev values. The fix: (1) initializes FLAGS=() as an array, (2) appends elements with FLAGS+=(--dev) and FLAGS+=(--threshold "$INPUT_THRESHOLD") keeping the threshold value double-quoted, and (3) expands the array as "${FLAGS[@]}" in both oss-health-scan command invocations. This eliminates the injection vector while preserving correct argument boundaries.

### Iteration 3

**Fixes applied:** unpinned-uses, missing-permissions

**Notes:**

Pinned all mutable action tags to full 40-character commit SHAs: actions/checkout@v6 → d23441a48e516b6c34aea4fa41551a30e30af803, actions/checkout@v4 → 11d5960a326750d5838078e36cf38b85af677262, actions/setup-node@v4 → 49933ea5288caeca8642d1e84afbd3f7d6820020. Added top-level `permissions: contents: read` to validate.yml (the workflow only reads code and runs tests). The other two workflow files (evidence-daily.yml and publish-cli.yml) already had appropriate permissions blocks.

