# HOL Guard

Runtime safety for supported local AI coding-agent harnesses.

This skill directly installs and invokes the HOL Guard runtime before mutation-bearing agent work. It uses Guard-owned detection, bootstrap/install, dry-run, doctor, protected launch, approvals, receipts, and status checks, and fails closed rather than launching an unprotected fallback.

The skill pins HOL Guard `3.0.12` for reproducible setup. Cloud connection and synchronization remain opt-in. Do not silently replace the pin with `latest`; update it only after explicit compatibility review.

With Hacktron CLI, after pulling this registry, enable the skill with:

```bash
hacktron skills enable hol-guard
```

With Claude Code, register the Hacktron marketplace and install the `hol-guard` plugin from it.
