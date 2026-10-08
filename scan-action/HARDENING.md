<!-- markdownlint-disable -->

# Hardening Report: dusan-maintains--oss-maintenance-log--scan-action/v1.7.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dusan-maintains--oss-maintenance-log--scan-action/v1.7.0** was hardened automatically. 2 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

The action uses `actions/setup-node@v4`, which is a mutable tag reference rather than a pinned 40-character commit SHA. This means the action could be silently updated to a different (potentially malicious) version without any change to this file.

Locations:

- `action.yml:30`

### script-injection (severity: high)

Sub-rule (a): Multiple `${{ }}` expressions are interpolated directly inside `run:` shell command strings, bypassing shell quoting and enabling script injection.

1. Line 50: `pr="${{ github.event.pull_request.number }}"` — the PR number from the GitHub event context is injected directly into the shell script. An attacker could craft a PR number containing shell metacharacters.
2. Line 51: `repo="${{ github.repository }}"` — the repository name (which can contain special characters) is injected directly into the shell script.
3. Line 60: `if [ "${{ steps.scan.outputs.critical }}" -gt 0 ]` — the step output is interpolated directly into the shell condition.
4. Line 61: `echo "::error::oss-health-scan found ${{ steps.scan.outputs.critical }} critical dependency health issue(s)."` — the step output is interpolated directly into the shell echo command.

All four should be moved to `env:` variables and referenced as `"$VAR"` in the shell script.

Locations:

- `action.yml:50`
- `action.yml:51`
- `action.yml:60`
- `action.yml:61`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection

**Notes:**

1. Pinned actions/setup-node@v4 to full commit SHA 49933ea5288caeca8642d1e84afbd3f7d6820020 with '# v4' comment for readability. 2. Fixed all four script-injection instances: moved ${{ github.event.pull_request.number }} to PR_NUMBER env var, ${{ github.repository }} to REPO env var, and both uses of ${{ steps.scan.outputs.critical }} to CRITICAL env var. Shell scripts now reference these as plain $PR_NUMBER, $REPO, and $CRITICAL variables.

