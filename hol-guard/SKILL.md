---
name: hol-guard
description: Protect supported local AI coding harnesses with HOL Guard before mutation-bearing tool work, verify Guard-owned protection state, and review blocked actions without bypassing native agent controls.
license: Apache-2.0
compatibility: Requires uv for optional isolated installation and a local AI coding harness supported by HOL Guard.
metadata:
  author: hashgraph-online
  version: "1.0.0"
  category: security
allowed-tools: Bash(*) Read
---

# HOL Guard

Use HOL Guard as a local runtime safety boundary before a supported coding agent performs mutation-bearing tool work. Keep the harness's own authentication, permissions, confirmations, sandboxing, and provider policies enabled.

## Safety rules

- Never read `.env` files or copy credentials into Guard commands.
- Never claim a harness is protected until HOL Guard itself reports a healthy protected state.
- Never bypass a Guard denial or approval queue by launching the raw harness directly.
- Never guess a harness identifier. Resolve it from `hol-guard detect --json`.
- Keep HOL Guard Cloud opt-in. Do not connect or sync unless the user explicitly requests it.
- Preserve native harness safeguards. Guard is an additional boundary, not a replacement for them.

## Install and verify

Probe the real CLI first:

```bash
hol-guard --version
```

If it is unavailable and the user authorized runtime setup, install the reviewed HOL Guard 3.0.0 release in an isolated tool environment:

```bash
uv tool install "hol-guard[cisco]==3.0.0"
hol-guard --version
```

Require the version check to report `3.0.0`. Do not silently replace the pin with `latest`, a prerelease, or a branch URL.

Resolve the supported local harness from Guard itself:

```bash
hol-guard status
hol-guard detect --json
```

Use only an exact supported harness identifier returned by `detect`. If no supported harness is found, stop mutation-bearing work instead of falling back to an unprotected session.

## Protect the harness

Run the Guard-owned setup and launch path:

```bash
hol-guard bootstrap
hol-guard install <detected-harness>
hol-guard run <detected-harness> --dry-run
hol-guard doctor <detected-harness> --json
hol-guard run <detected-harness>
hol-guard status
```

The dry run and doctor check must succeed before reporting protection. If bootstrap, install, dry-run, doctor, or protected launch fails, stop and report the exact failing command.

## Blocked work and approvals

Inspect Guard-owned decisions before acting:

```bash
hol-guard approvals
hol-guard approvals open
hol-guard receipts
hol-guard diff <detected-harness>
```

Only when the user has reviewed the risk reason and explicitly chosen a terminal decision:

```bash
hol-guard approvals approve <request-id>
hol-guard approvals deny <request-id>
```

A prior approval does not authorize a different request. Never modify harness configuration manually to bypass a Guard decision.

## Evidence

Prefer Guard's own evidence surfaces:

```bash
hol-guard doctor <detected-harness> --json
hol-guard status
hol-guard receipts
hol-guard inventory
hol-guard abom --format json
hol-guard events
```

Report only evidence actually returned by Guard. Do not invent successful protection, approvals, or audit results.

## Boundary

This skill protects a supported local agent harness before tool execution. It does not replace repository policy, code review, operating-system isolation, application authorization, provider-side access controls, or remote-service safety checks.
