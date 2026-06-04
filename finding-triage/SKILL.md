---
name: finding-triage
description: Interactively validate and triage Hacktron findings against the actual source code and (optionally) a live deployment, separate true positives from false positives, adjust severity, then either propose fixes and commit them or set the finding's state in Hacktron (true_positive, false_positive, accepted_risk, resolved). Talks to the Hacktron REST API with curl, reading the latest API docs at runtime. Use when the user asks to validate, triage, confirm, filter, or fix Hacktron scan or PR-review findings, or mentions false positives in a Hacktron scan.
license: MIT
compatibility: Requires curl and jq, plus network access to api.hacktron.ai and docs.hacktron.ai, a Hacktron API key, and a local checkout of the affected source. Deployment access is optional for dynamic validation.
metadata:
  author: hacktron
  version: "2.0.0"
  category: security
allowed-tools: Bash(*) Read Grep Glob Write
---

# Finding Triage

An **interactive** assistant for triaging Hacktron findings. You drive a
conversation: fetch the findings, confirm where the source lives, optionally
validate against a live deployment, triage each finding, then either propose
fixes and commit them or update the finding's state in Hacktron. You are the
validator and the fixer — you read the code and reason yourself.

This skill does **not** ship API client scripts. The Hacktron REST API is the
source of truth and may change, so you read the live docs and call it with
`curl`. **Stop and ask the user at each decision point below** — do not run end
to end silently.

## Setup: API key + current API shape

1. The key goes in the `X-Api-Key` header. Have the user export it; never
   hardcode or echo it:

```bash
export HACKTRON_API_KEY="hacktron_..."
```

2. Smoke-test the key (a `200` with `data`/`total`/`page`/`limit` means it works):

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://api.hacktron.ai/v1/scans?limit=1" \
  -H "X-Api-Key: $HACKTRON_API_KEY"
```

3. Pull the **latest** API reference before making real calls — endpoints and
   fields can change. The index lists every page:

```bash
curl -s https://docs.hacktron.ai/llms.txt
```

Read the relevant `.md` pages from that index as needed, especially:
- `api-reference/findings/list-findings.md` — list/filter findings org-wide
- `api-reference/findings/update-finding.md` — change state/severity
- `api-reference/scans/export-scan-findings.md` — SARIF/CSV/JSON export
- `api-reference/pagination-filtering.md` — paging & filter conventions

The curl snippets below are a convenience; if the docs disagree, **follow the
docs.**

## Workflow

```
- [ ] Step 1: Fetch findings
- [ ] Step 2: Confirm the source location
- [ ] Step 3: Ask about live-deployment validation (optional)
- [ ] Step 4: Triage each finding (static + optional dynamic)
- [ ] Step 5: Present results, ask what to do next
- [ ] Step 6a: Propose fixes and commit   (if they want fixes)
- [ ] Step 6b: Set finding state in Hacktron   (if they don't)
- [ ] Step 7: Write the triage report
```

### Step 1: Fetch findings

All unresolved findings org-wide (default `state=open`), newest first. Findings
list endpoints page with `page`/`limit` (max `limit=100`) and report `total`:

```bash
curl -s "https://api.hacktron.ai/v1/findings?state=open&limit=100&page=1" \
  -H "X-Api-Key: $HACKTRON_API_KEY" | jq '.total, (.data | length)'
```

Iterate pages until you have all `total` items. Narrow with filters (AND
semantics) — e.g. `&severity=critical` or `&scan_id=<uuid>`:

```bash
curl -s "https://api.hacktron.ai/v1/findings?state=open&severity=critical&limit=100&page=1" \
  -H "X-Api-Key: $HACKTRON_API_KEY" | jq '.data[] | {id, severity, title, affected_file}'
```

If the user wants a SARIF for a specific scan, export it:

```bash
curl -s "https://api.hacktron.ai/v1/scans/<scan-id>/findings/export?format=sarif" \
  -H "X-Api-Key: $HACKTRON_API_KEY" > findings.sarif
```

The list endpoint returns a summary per finding (`id`, `title`, `category`,
`severity`, `state`, `description`, `affected_file` — a repo-relative path that
may include a `:line-start-line-end` suffix — `affected_code`,
`proof_of_concept`). For full triage context, **fetch the finding by id** — it
adds reachability evidence you should use in Step 4:

```bash
curl -s "https://api.hacktron.ai/v1/findings/<finding-id>" \
  -H "X-Api-Key: $HACKTRON_API_KEY" | jq '{repo_url, scan_type, taint_path, call_graph, mermaid_trace, triage_thread, occurrence_count}'
```

Key extra fields: `repo_url` (which repo the path belongs to), `taint_path` /
`call_graph` / `mermaid_trace` (the source→sink data flow the scanner traced),
and `triage_thread` (prior triage comments). Show the user the queue and confirm
which findings to work through.

### Step 2: Confirm the source location

The `affected_file` paths are repo-relative; the finding's `repo_url` tells you
which repo they belong to. Find the local checkout:

1. Check the current working directory first. If it matches `repo_url` and the
   `affected_file` paths resolve under the pwd, use it — tell the user "using the
   source in the current directory."
2. If they don't resolve, **ask the user for the path** to the local checkout
   (mention the `repo_url` so they grab the right repo).
3. Confirm the checkout matches the scanned code (same branch/commit if known).
   Missing files or lines mean those findings are `low` confidence — say so.

### Step 3: Ask about live-deployment validation (optional)

Ask: **"Validate these against a live deployment, or source-only?"**

If they want dynamic validation, gather and confirm:
- Base URL / host of the deployment
- Auth (headers, token, cookies) and which environment it is (**prefer
  staging/test, not production**)
- Scope limits (paths to avoid, rate limits)

**Safety rules for dynamic validation:**
- Only run **non-destructive, read-only** checks unless the user explicitly
  authorizes active testing of a specific finding.
- Never run a PoC against production without clear, explicit consent.
- Stay strictly within the scope and target the user gave you.

If they decline, do source-only validation and note reachability is inferred
from code, not confirmed live.

### Step 4: Triage each finding

For **each** finding, do the work yourself — do not trust the scanner's claim.

**Static (always):**
1. Read the affected file at the reported lines plus ~20 lines of context.
   Confirm the flagged code exists as described.
2. Look for mitigations the scanner missed: bounds checks, input validation,
   sanitization/encoding, auth/permission checks, allow-lists, safe APIs,
   parameterized queries, resource limits.
3. Trace reachability with `Grep`/`Glob`: is the path reachable from
   attacker-controlled input? Use the finding's `taint_path` / `call_graph` /
   `mermaid_trace` as the scanner's hypothesis, then **verify each hop in the
   real code** — don't take the trace on faith. Unreachable code is usually a
   false positive.
4. Confirm the bug class fits (e.g. "SQL injection" on a parameterized query is
   a false positive).

**Dynamic (only if Step 3 was approved):**
5. Reproduce the finding's `proof_of_concept` against the deployment within the
   agreed scope. A confirmed live repro is strong evidence of a true positive.

Then assign, per finding:
- **verdict**: `true_positive` | `false_positive`
- **confidence**: `high` (conclusive) | `medium` (strong but uncertain) | `low`
  (could not fully validate — file missing, ambiguous, needs a human)
- **adjusted severity**: `critical` | `high` | `medium` | `low` | `info`, based on
  realistic exploitability — attack prerequisites, impact scope, exploitation
  difficulty — not the scanner's default.

### Step 5: Present results, ask what to do next

Show a short per-finding summary (verdict, confidence, severity, one-line
reasoning). Then **ask how to proceed**:
- "Fix the confirmed true positives?" → Step 6a
- "Or just record the triage outcome in Hacktron?" → Step 6b
- Per finding is fine too (fix some, record others).

### Step 6a: Propose fixes and commit

Fix **only** `high`-confidence `true_positive` findings. For each:

1. **Propose the fix first** — describe the change and show the diff before
   applying, so the user can approve.
2. Implement the smallest correct fix. Use the finding's `remediation` as a
   starting point but verify it against the real code and match existing style.
   Fix the root cause, not the symptom. Don't refactor unrelated code.
3. **One commit per finding**, so each fix is reviewable and revertible:

```bash
git add <changed-files>
git commit -m "$(cat <<'EOF'
fix(security): <short description of the fix>

Addresses Hacktron finding <finding-id> (<category>, <severity>).
<one line on the root cause and how the fix removes it>
EOF
)"
```

- **Never push or open a PR** unless the user explicitly asks.
- If a fix is risky or needs design decisions, don't guess — leave it and flag it.

### Step 6b: Set finding state in Hacktron

`PATCH /v1/findings/{id}` with at least one of `state` / `severity`. Use `reason`
when one justification covers both, or `state_reason` / `severity_reason` when
they differ (max 2000 chars each):

```bash
curl -s -X PATCH "https://api.hacktron.ai/v1/findings/<finding-id>" \
  -H "X-Api-Key: $HACKTRON_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "state": "false_positive",
    "severity": "low",
    "reason": "Query uses bound parameters; user input never concatenated. Not exploitable as reported."
  }'
```

State meaning (the Hacktron triage states):
- `true_positive` — confirmed real (fix pending elsewhere)
- `false_positive` — not a real issue
- `accepted_risk` — real but the user chooses to accept it
- `resolved` — set after a Step 6a fix is merged/deployed
- `severity` uses `info` (not `informational`).
- Only sync `high`/`medium`-confidence verdicts. Leave `low` for human review.

The PATCH response returns only the updated `state` and `severity`. Confirm with
`GET /v1/findings/{id}` if you need the full record.

### Step 7: Write the triage report

```markdown
# Triage Report — <scan-id or "org-wide, state=open">

## Summary
- Triaged: N   | TP: N   | FP: N   | High confidence: N
- Dynamic validation: yes/no (target: <env>)
- Fixed & committed: N   | State updated in Hacktron: N

## Findings
### [SEVERITY→adjusted] <title>  (`finding-id`)
- Verdict: true_positive | false_positive  (confidence: high/medium/low)
- File: path:line-range
- Evidence: <static reasoning; live repro result if dynamic>
- Mitigations found: <defensive code that reduces/removes the risk, or "none">
- Action: fixed (<commit sha>) | state set to <state> | left for human review
```

## Rules

- This flow is interactive — stop and ask at Steps 2, 3, and 5.
- The Hacktron API is the source of truth: read `llms.txt` + the endpoint docs
  before calling, and follow the docs over the snippets here if they differ.
- Never hardcode or echo the API key; read it from `$HACKTRON_API_KEY`.
- Always read the actual source before deciding. No verdict without reading code.
- Dynamic validation is read-only by default; active testing needs explicit,
  scoped consent and never targets production without it.
- Only fix `high`-confidence `true_positive` findings, only when asked, and never
  push or open a PR without explicit instruction.
- Never set state from a `low`-confidence verdict; surface it for a human.
- If the local checkout doesn't match the scanned code, mark affected findings
  `low` confidence and note the mismatch.
