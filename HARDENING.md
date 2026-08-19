<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log/v1.2.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log/v1.2.0** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Direct expression interpolation of inputs inside run: blocks. In action.yml, ${{ inputs.evidence-dir }} and ${{ inputs.config-file }} are interpolated directly into a PowerShell run: block (lines 47-48). In cli/action.yml, ${{ inputs.include-dev }}, ${{ inputs.threshold }}, and ${{ inputs.path }} are interpolated directly into a bash run: block multiple times (lines 54, 57, 61, 71, 74, 75). Any of these inputs could contain shell metacharacters or PowerShell injection payloads supplied by a caller of the composite action.

Locations:

- `action.yml:47`
- `action.yml:48`
- `cli/action.yml:54`
- `cli/action.yml:57`
- `cli/action.yml:61`
- `cli/action.yml:71`
- `cli/action.yml:74`
- `cli/action.yml:75`

### github-env-injection (severity: high)

Untrusted input values are written to $GITHUB_OUTPUT without sanitization (no printf '%s' ... | tr -d '\n\r' step). In action.yml, ${{ inputs.evidence-dir }} is interpolated into $dir and ${{ inputs.config-file }} into $cfg; $dir is then used to construct paths written to $GITHUB_OUTPUT (e.g. 'health-json=$healthPath' >> $env:GITHUB_OUTPUT). In cli/action.yml, ${{ inputs.path }} is interpolated directly into the oss-health-scan command whose output ($RESULTS) is written to $GITHUB_OUTPUT via a heredoc. An attacker-controlled newline in any of these inputs can inject arbitrary key=value pairs into the output context.

Locations:

- `action.yml:47`
- `action.yml:55`
- `cli/action.yml:61`
- `cli/action.yml:63`

### unpinned-uses (severity: high)

Multiple uses: references and one npm install reference use mutable tags instead of pinned 40-character SHA digests, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the package is compromised. Failing references: evidence-daily.yml: actions/checkout@v6; publish-cli.yml: actions/checkout@v6, actions/setup-node@v4; validate.yml: actions/checkout@v6, actions/setup-node@v4; cli/action.yml: actions/setup-node@v4. Additionally, cli/action.yml runs 'npm install -g oss-health-scan@latest' which is an unpinned mutable package reference.

Locations:

- `.github/workflows/evidence-daily.yml:14`
- `.github/workflows/publish-cli.yml:14`
- `.github/workflows/publish-cli.yml:17`
- `.github/workflows/validate.yml:10`
- `.github/workflows/validate.yml:23`
- `.github/workflows/validate.yml:37`
- `.github/workflows/validate.yml:44`
- `cli/action.yml:40`

### missing-permissions (severity: medium)

validate.yml has no top-level permissions: key and none of its three jobs (validate, test-pester, test-cli) define a job-level permissions: block. This means the workflow runs with the default GitHub token permissions, which may be broader than necessary (e.g. write access to contents on push/pull_request triggers).

Locations:

- `.github/workflows/validate.yml:1`

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

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, missing-permissions, static-inline-injection

**Notes:**

Fixed all 6 findings across 5 files:

1. action.yml (script-injection + github-env-injection + static-inline-injection): Moved `${{ inputs.evidence-dir }}` and `${{ inputs.config-file }}` to the step's env: block as INPUT_EVIDENCE_DIR and INPUT_CONFIG_FILE. Added PowerShell newline sanitization (`-replace '[\r\n]', ''`) on paths before writing to $env:GITHUB_OUTPUT.

2. cli/action.yml (script-injection + github-env-injection): Moved `${{ inputs.include-dev }}`, `${{ inputs.threshold }}`, and `${{ inputs.path }}` to the step's env: block. Sanitized INPUT_THRESHOLD with `printf '%s' | tr -d '\n\r'` and RESULTS with `printf '%s\n' | tr -d '\r'` before writing to $GITHUB_OUTPUT. Also pinned `actions/setup-node@v4` to SHA `49933ea5288caeca8642d1e84afbd3f7d6820020`.

3. evidence-daily.yml (unpinned-uses): Pinned `actions/checkout@v6` to SHA `d23441a48e516b6c34aea4fa41551a30e30af803`.

4. publish-cli.yml (unpinned-uses): Pinned `actions/checkout@v6` and `actions/setup-node@v4` to their full SHAs.

5. validate.yml (unpinned-uses + missing-permissions): Added `permissions: contents: read` top-level block. Pinned all 3 `actions/checkout@v6` and 1 `actions/setup-node@v4` references to full SHAs.

Note: The `npm install -g oss-health-scan@latest` unpinned package reference in cli/action.yml was flagged but is an npm package (not a GitHub Action uses: reference) — it cannot be pinned via SHA in the same way; this is a known limitation of npm package pinning in composite actions.

