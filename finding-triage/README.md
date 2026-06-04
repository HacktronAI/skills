# Finding Triage

An **interactive** assistant for triaging Hacktron scan / PR-review findings. It
fetches findings, confirms where the source lives, optionally validates against a
live deployment, decides true vs false positive, and then either proposes fixes
(committing each one) or records the verdict back in Hacktron.

It talks to the Hacktron REST API directly with `curl`, reading the latest API
docs at runtime — there are no bundled API client scripts to drift out of date.

## What it does (interactive flow)

1. Fetches findings from the Hacktron API — all unresolved (`state=open`)
   findings org-wide by default, or filtered by severity / scan.
2. Confirms the source location (uses the current directory if it matches,
   otherwise asks).
3. Asks whether to validate against a live deployment, and gathers the target +
   scope if so (read-only by default; active testing needs explicit consent).
4. Triages each finding (static source analysis + optional dynamic repro),
   assigning a verdict, confidence, and adjusted severity.
5. Presents results and asks what to do next, then either:
   - fixes high-confidence true positives and commits each fix separately
     (never pushes without instruction), or
   - sets the finding's state in Hacktron (`true_positive`, `false_positive`,
     `accepted_risk`, `resolved`).
6. Produces a triage report.

## Requirements

- `curl` and `jq`
- Network access to `api.hacktron.ai` and `docs.hacktron.ai`
- A Hacktron API key (sent in the `X-Api-Key` header)
- A local checkout of the affected source
- Optional: network access to a deployment for dynamic validation

## API reference

The skill reads the live docs before calling the API:

- Index: https://docs.hacktron.ai/llms.txt
- [List findings](https://docs.hacktron.ai/api-reference/findings/list-findings)
- [Update finding](https://docs.hacktron.ai/api-reference/findings/update-finding)
- [Export scan findings](https://docs.hacktron.ai/api-reference/scans/export-scan-findings)
- [Authentication](https://docs.hacktron.ai/api-reference/authentication)

## Usage

See [SKILL.md](./SKILL.md) for the full interactive triage workflow.
