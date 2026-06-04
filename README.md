# Hacktron Skills

Community-maintained skills for offensive and defensive security capabilities. Built for security researchers, engineers, and bug hunters.

## What are Skills?

Skills extend AI agents with specialized security capabilities. When enabled, skills provide domain-specific instructions, scripts, and references that help agents perform complex security tasks.

This repository follows the [Agent Skills specification](https://agentskills.io/specification).

## Usage

### With Claude Code

This repo is also a [Claude Code plugin marketplace](https://docs.claude.com/en/docs/claude-code/plugins-reference). Each skill is installable as a plugin.

```
# Register the marketplace
/plugin marketplace add HacktronAI/skills

# Browse and install from the menu
/plugin menu

# Or install a specific skill directly
/plugin install finding-triage@hacktron
```

Install from a local clone instead:

```bash
git clone https://github.com/HacktronAI/skills.git
```

```
# From the parent directory of the clone
/plugin marketplace add ./skills
/plugin install finding-triage@hacktron
```

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

| Skill | Description | Sources |
|-------|-------------|---------|
| [finding-triage](./finding-triage/) | Interactively triage Hacktron findings against source (and optionally a live deployment), then fix + commit confirmed issues or set their state in Hacktron | - |
| [patch-diff-analyzer](./patch-diff-analyzer/) | Reverse-engineer compiled binaries (JARs, DLLs) to analyze security patches | - |

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

