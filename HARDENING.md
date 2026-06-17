<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log/v1.6.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **dusan-maintains--oss-maintenance-log/v1.6.0** was hardened automatically. 5 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

action.yml directly interpolates ${{ inputs.evidence-dir }} and ${{ inputs.config-file }} inside a run: PowerShell block (rule a). An attacker-controlled caller can supply newlines or PowerShell metacharacters in these inputs to inject arbitrary commands. Offending lines: `$dir = "${{ inputs.evidence-dir }}"` and `$cfg = "${{ inputs.config-file }}"`. Fix: pass inputs via env: variables and reference them as $env:DIR / $env:CFG inside the script.

Locations:

- `action.yml:47`
- `action.yml:48`

### script-injection (severity: high)

cli/action.yml directly interpolates ${{ inputs.include-dev }}, ${{ inputs.threshold }}, and ${{ inputs.path }} inside run: bash blocks (rule a). An attacker-controlled caller can supply shell metacharacters or newlines in these inputs to inject arbitrary commands. Offending lines include: `if [ "${{ inputs.include-dev }}" = "true" ]`, `if [ "${{ inputs.threshold }}" != "0" ]`, `FLAGS="$FLAGS --threshold ${{ inputs.threshold }}"`, `RESULTS=$(oss-health-scan ${{ inputs.path }} --json $FLAGS ...)`, `oss-health-scan ${{ inputs.path }} $FLAGS --ci || true`. Fix: move all inputs into env: variables and reference them as quoted "$VAR" inside the script.

Locations:

- `cli/action.yml:49`
- `cli/action.yml:52`
- `cli/action.yml:53`
- `cli/action.yml:57`
- `cli/action.yml:72`
- `cli/action.yml:75`
- `cli/action.yml:76`

### unpinned-uses (severity: high)

cli/action.yml references `actions/setup-node@v4` using a mutable tag instead of a pinned 40-character commit SHA. A tag can be moved to point to a different (potentially malicious) commit, enabling supply-chain attacks. Fix: pin to a full SHA, e.g. `actions/setup-node@1d0ff469b4a71a8d39c8e168e8e3e3c7d957c7c4 # v4`.

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

Fixed all three finding types across two files:

1. action.yml: Moved `${{ inputs.evidence-dir }}` and `${{ inputs.config-file }}` from the PowerShell run: block into the env: map as EVIDENCE_DIR and CONFIG_FILE. Script now reads them via `$env:EVIDENCE_DIR` and `$env:CONFIG_FILE`.

2. cli/action.yml: Moved `${{ inputs.include-dev }}`, `${{ inputs.threshold }}`, and `${{ inputs.path }}` from the bash run: block into the env: map as INCLUDE_DEV, THRESHOLD, and SCAN_PATH. All references in the script use the safe environment variable forms.

3. cli/action.yml: Pinned `actions/setup-node@v4` to full commit SHA `49933ea5288caeca8642d1e84afbd3f7d6820020` with `# v4` comment for readability.

### Iteration 2

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed three security findings across two files:

1. cli/action.yml (script-injection): Quoted $FLAGS as "$FLAGS" in both oss-health-scan invocations (--json run and --ci run) to prevent shell metacharacter injection from attacker-controlled threshold input.

2. action.yml (github-env-injection): Added PowerShell newline sanitization for $healthPath and $manifestPath before writing to $GITHUB_OUTPUT: `$safeHealthPath = $healthPath -replace '[\r\n]', ''` and `$safeManifestPath = $manifestPath -replace '[\r\n]', ''`.

3. cli/action.yml (github-env-injection): Sanitized $RESULTS output using `printf '%s' | tr -d '\r'` in the heredoc block; sanitized $AVG and $CRIT by computing SAFE_AVG and SAFE_CRIT via `printf '%s' | tr -d '\n\r'` before writing to GITHUB_OUTPUT.

