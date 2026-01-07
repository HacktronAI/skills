# CVSS v3.1 Guidance (General)

Use this when choosing CVSS metrics from a report. Keep the scoring evidence-driven and conservative.

## Evidence-First Scoring
- Every metric must be supported by report evidence. If evidence is missing, use `needs-info`.
- Avoid worst-case scoring; choose the minimum credible impact based on what is proven.
- Separate **preconditions** (environment/state) from **attacker actions** (steps).

## Define the Affected System
- Identify the vulnerable component and its security authority (client, server, service, library).
- Score CIA impact on that component only. Downstream impacts are discussed in notes, not in base metrics.

## Metric Guidance
- **AV (Attack Vector)**: Where must the attacker be relative to the affected system?
  - `N`: exploitable remotely without local access or preconditions.
  - `A`: adjacent network required (same subnet, Bluetooth, etc.).
  - `L`: requires local access on the affected system.
  - `P`: requires physical access.

- **AC (Attack Complexity)**: Are there conditions beyond attacker control?
  - `L`: no special conditions or environment setup required.
  - `H`: requires specific configuration, race conditions, rare states, or dependent services.

- **PR (Privileges Required)**: Privileges on the affected system before exploitation.
  - `N`: none.
  - `L`: basic user privileges required.
  - `H`: admin or high privileges required.

- **UI (User Interaction)**: Must a user perform an action?
  - `N`: no user action required.
  - `R`: user must click, open, approve, or perform a step.

- **S (Scope)**: Does exploitation cross a security authority boundary?
  - `U`: impact stays within the vulnerable component's authority.
  - `C`: impact crosses into a different authority (tenant breakout, container escape, cross-service access).

- **C/I/A (Impact)**: Actual effect on the vulnerable component.
  - `N`: no meaningful impact.
  - `L`: limited impact (small disclosure, minor data modification, reduced availability).
  - `H`: total loss of confidentiality/integrity/availability.

## Common Pitfalls
- Treating a network protocol as AV:N even when the attacker needs local access or a local precondition.
- Scoring CIA based on downstream systems rather than the vulnerable component.
- Assuming sensitive data or admin privileges without evidence.
- Ignoring prerequisites (special config, existing session, agent running).

## Calibration
- If vendor severity is provided and your CVSS differs by 2+ tiers, re-check metrics.
- If you still cannot justify the gap with explicit evidence, mark `needs-info` and explain the divergence.

## Metric Justification Template
Use this template to ensure traceability:

```
AV: <metric> — evidence from report
AC: <metric> — evidence from report
PR: <metric> — evidence from report
UI: <metric> — evidence from report
S: <metric> — evidence from report
C: <metric> — evidence from report
I: <metric> — evidence from report
A: <metric> — evidence from report
```
