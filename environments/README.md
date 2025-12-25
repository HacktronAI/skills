# Environments

Environments are isolated feedback setups that allow AI agents to interact with real systems while solving security challenges. Unlike static analysis where an agent can only hypothesize about vulnerabilities, environments provide live feedback - the agent submits an attempt, the system responds, and the agent learns from the result.

## What's in an Environment?

Each environment typically includes:

- **Target services** - The systems to analyze/attack (WAFs, web apps, binaries)
- **Feedback mechanisms** - Logs, responses, and signals that help the agent iterate
- **Hidden objectives** - Flags or goals the agent must earn through successful exploitation

## Why Separate from Skills?

Environments are separate from skills. A skill defines the challenge (what to solve, what source code to analyze, what hints to provide). An environment provides the runtime infrastructure where the agent tests their solutions.

The agent sees the skill but interacts with the environment blindly - they can't read the flag file, they must capture it.

This creates a genuine learning loop:

```
Analyze → Hypothesize → Test → Get Feedback → Iterate → Solve
```

## Available Environments

| Environment | Description |
|-------------|-------------|
| `vercel-waf-env` | Coraza WAF protecting a vulnerable Next.js 16 backend |

## Usage

```bash
cd environments/vercel-waf-env
docker-compose up --build
```

