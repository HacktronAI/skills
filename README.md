# Hacktron Skills

Community-maintained skills for offensive and defensive security capabilities. Built for security researchers, engineers, and bug hunters.

## What are Skills?

Skills extend AI agents with specialized security capabilities. When enabled, skills provide domain-specific instructions, scripts, and references that help agents perform complex security tasks.

This repository follows the [Agent Skills specification](https://agentskills.io/specification).

## Usage

### With Hacktron CLI

```bash
# Pull the skills registry
hacktron skills pull

# List available skills
hacktron skills list

# Enable a skill
hacktron skills enable patch-diff-analyzer

# Disable a skill
hacktron skills disable patch-diff-analyzer
```

### With Hacktron VSCode Extension

Skills are automatically discovered and can be enabled/disabled from the extension settings.

## Available Skills

| Skill | Description |
|-------|-------------|
| [patch-diff-analyzer](./patch-diff-analyzer/) | Reverse-engineer compiled binaries (JARs, DLLs) to analyze security patches |
| [waf-bypass-hunter](./waf-bypass-hunter/) | Find WAF bypass techniques using parser differentials |

## Environments

Environments are isolated feedback setups for security challenges. Unlike skills (which define *what* to solve), environments provide the runtime infrastructure where agents *test* their solutions.

The agent sees the skill but interacts with the environment blindly - they can't read the flag, they must capture it.

```
Analyze → Hypothesize → Test → Get Feedback → Iterate → Solve
```

| Environment | Description |
|-------------|-------------|
| [vercel-waf-env](./environments/vercel-waf-env/) | Coraza WAF + vulnerable Next.js 16 backend |


**Learn more about vercel env:** [React2Shell: Vercel WAF Bypass](https://hacktron.ai/blog/react2shell-vercel-waf-bypass)


See [environments/README.md](./environments/README.md) for details.

## Compatible Skill Repositories

Skills from other repositories that follow the [Agent Skills specification](https://agentskills.io/specification) can be used with Hacktron:

- **[SecOpsAgentKit](https://github.com/AgentSecOps/SecOpsAgentKit)** - 25+ security operations skills including SAST, DAST, container scanning, and secret detection
- **[Raptor Skills](https://github.com/gadievron/raptor/tree/main/.claude/skills)** - Additional security research skills

To use skills from other repositories, manually copy them into `~/.hacktron/skills/`:

```bash
# Copy individual skills from other repos
cp -r /path/to/other-repo/skill-name ~/.hacktron/skills/
```

>  **Security Warning**: Skills can execute arbitrary commands on your machine. Always review the `SKILL.md` and any scripts before adding skills from third-party sources. Only the official [HacktronAI/skills](https://github.com/HacktronAI/skills) repository is reviewed and validated for security.

> **Note**: The `hacktron skills pull` command only pulls from the official HacktronAI/skills repository. Third-party skills must be manually copied to ensure users consciously review what they're installing.

## Creating Skills

Skills follow the [Agent Skills specification](https://agentskills.io/specification). Each skill is a directory containing:

```
skill-name/
├── SKILL.md          # Required - YAML frontmatter + instructions
├── scripts/          # Optional - executable scripts
├── references/       # Optional - additional documentation
└── assets/           # Optional - templates, data files
```

### SKILL.md Format

```markdown
---
name: skill-name
description: What the skill does and when to use it.
license: MIT
compatibility: Required tools or environment
metadata:
  author: your-name
  version: "1.0.0"
---

# Skill Name

Instructions for the agent...
```

### Contributing

1. Fork this repository
2. Create your skill following the spec
3. Test with `hacktron skills enable your-skill`
4. Open a PR

All skills are reviewed for security before being merged.

## License

MIT

