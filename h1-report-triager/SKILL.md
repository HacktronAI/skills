---
name: h1-report-triager
description: Triage HackerOne vulnerability reports from report URLs or report.md/report.txt content; assess scope, reproducibility, impact, and severity using CVSS v3.1, and produce a triage decision with missing-info questions. Use when analyzing or validating HackerOne web bug reports.
compatibility: ability to run python code and access to internet
---

# H1 Report Triager

## Inputs
- Report file: `report.md`, `report.txt`, or any local Markdown/text file.
- Report URL: public or private HackerOne report URL or numeric ID.
- Raw pasted report text.

## Quick Start
1. If you have a HackerOne URL or report ID, fetch Markdown:
   - `python3 scripts/fetch_report.py https://hackerone.com/reports/792927 -o report.md`
   - For private reports, pass credentials: `--username <h1_user> --token <h1_token>` or set `H1_USER` and `H1_TOKEN`.
   - The fetcher requires `requests` (`pip install requests`).
2. If you already have a local file, open and read it directly.
3. If you have raw report text, treat it as the report body.

## Triage Workflow
1. Extract key facts: target asset, vulnerability class, affected components, authentication needed, and the reported impact.
2. Check scope: confirm the asset is in scope; if scope data is missing, call it out.
3. Reproducibility: verify the steps, inputs, and environment details are sufficient. If not, flag missing info.
4. Impact analysis: document actual consequences, attacker requirements, and user interaction.
5. Define the affected system and attacker position before scoring (client vs server, local vs remote).
6. CVSS scoring: build a CVSS 3.1 JSON and run the calculator script (see below). Use `references/cvss-guidance.md` when selecting metrics.
7. Severity calibration: if vendor severity is provided and your CVSS result differs by 2+ tiers, re-check metrics and flag uncertainty.
8. Decision: mark `valid`, `needs-info`, `duplicate`, or `not-applicable` and justify.
9. Missing info/questions: include targeted questions whenever evidence is weak or incomplete.

## CVSS v3.1 Scoring
Create a JSON file with metrics and run the calculator:

```json
{
  "version": "3.1",
  "AV": "N",
  "AC": "L",
  "PR": "N",
  "UI": "N",
  "S": "U",
  "C": "H",
  "I": "H",
  "A": "N"
}
```

Run:
- `python3 scripts/cvss31_score.py -i cvss.json`

Use the output base score, severity, and vector in your triage report.

### CVSS Guardrails
- Score CIA impact on the affected system only; do not import impact from downstream or remote systems.
- If exploitation requires local access or preconditions (specific config, pre-existing session, local agent), do not use AV:N.
- Treat prerequisites outside attacker control as higher complexity (AC:H) or higher privileges (PR:L/H).
- Do not assume worst-case metrics; if details are missing, mark `needs-info` and list questions.
- Provide a one-line justification for each metric (AV/AC/PR/UI/S/C/I/A) that cites report evidence.
- If your score conflicts with vendor severity by 2+ tiers and you cannot justify the difference, mark `needs-info`.

## Output Format
Provide a concise Markdown report with these sections:
- Summary
- Scope Check
- Reproduction & Evidence
- Impact Analysis
- CVSS (metrics JSON, score, severity, vector, and per-metric justification)
- Triage Decision
- Missing Info / Questions (required when evidence is weak)
- Remediation Notes

## Guardrails
- Do not invent evidence; default to `needs-info` when details are missing.
- Do not include or request secrets; only fetch private reports with user-supplied credentials.
