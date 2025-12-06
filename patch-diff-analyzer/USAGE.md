# Patch Diff Analyzer - Agent Guide

## Quick Decision Flow

- Binary files provided? → Decompile first, then analyze
- Git repo with versions? → Skip decompilation, use git tags directly
- Unknown binary type? → Ask user or use bash to identify

## Prerequisites

- Java JARs: Requires jadx, jd-cli, or cfr
- NET DLLs: Requires ilspycmd or monodis
- Check: `command -v jadx || command -v jd-cli`

## Binary Identification (CRITICAL)

Before decompiling, identify which file is patched:

- Version numbers: Higher version = patched (1.2.4 > 1.2.3)
- Names: patched.jar, fixed.jar, new.jar = patched
- Timestamps: `ls -lt` - newer = patched (unreliable if copied)
- When unclear: **ALWAYS ask user**

## Workflow A: Binary Analysis (JAR/DLL)

### 1. Setup Workspace

```bash
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/setup-workspace.sh myanalysis
```

Creates git repo with proper structure.

### 2. Extract Proprietary Code Only (WAR/Large JARs)

**CRITICAL**: Skip third-party libraries to save time.

```bash
# Identify proprietary packages first
unzip -l app.war | grep "WEB-INF/classes" | head -30

# Extract only proprietary code (e.g., com/acme/*)
mkdir temp-unpatched
cd temp-unpatched && unzip ./unpatched.war "WEB-INF/classes/com/acme/*"
cd WEB-INF/classes && jar cf ../../../acme-unpatched.jar . && cd ../../..

# Repeat for patched version
mkdir temp-patched
cd temp-patched && unzip ./patched.war "WEB-INF/classes/com/acme/*"
cd WEB-INF/classes && jar cf ../../../acme-patched.jar . && cd ../../..
```

### 3. Decompile Unpatched Version

```bash
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/decompile-jar.sh ./unpatched.jar ./myanalysis/decompiled/
# For DLL: extension_script on decompile-dll.sh ../../unpatched.dll ./myanalysis/decompiled/
```

### 4. Commit Unpatched

```bash
cd ./myanalysis && 
git add -A && git commit -m "Unpatched version" && git tag unpatched
```

### 5. Decompile Patched Version

```bash
rm -rf decompiled/*
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/decompile-jar.sh ./patched.jar ./myanalysis/decompiled/
# For DLL: extension_script on decompile-dll.sh ../../patched.dll ./myanalysis/decompiled/
```

### 6. Commit Patched

```bash
cd ./myanalysis && 
git add -A && git commit -m "Patched version" && git tag patched
```

## Workflow B: Existing Git Repo

If code is already in git with version tags:

```bash
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/analyze-diff.sh .
```

Script auto-detects unpatched/patched tags or uses last 2 commits.
## Generate Diff

```bash
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/analyze-diff.sh .
```

**Outputs**:

- `patch-analysis.diff` - complete diff
- `changed-files.txt` - list of modified files

## Security Analysis Process

### 1. Filter Third-Party Libraries FIRST

**MANDATORY**: Separate proprietary from third-party changes.

```bash
# Review changed files
cat changed-files.txt | head -100

# Identify and skip common third-party prefixes:
# com.fasterxml.jackson.*, org.springframework.*, org.hibernate.*
# org.apache.*, com.google.*, io.netty.*, javax.*, jakarta.*

# Extract proprietary changes only
grep "^decompiled/sources/" changed-files.txt | \
  grep -v "/com/fasterxml/" | grep -v "/org/springframework/" | \
  grep -v "/org/hibernate/" | grep -v "/org/apache/"
```

**Report both counts**:

- Total changes: X files
- Third-party library updates: Y files (Jackson, Spring, etc.)
- Proprietary code changes: Z files (focus here)

### 2. Read Complete Diff

```bash
# Read the entire diff file - DO NOT use grep/filtering
cat patch-analysis.diff
```

### 3. Identify Security Changes

Look for:

- Input validation added where missing
- Sanitization/encoding of user data
- Auth/authorization checks introduced
- Bounds checking before array access
- Type checking or casting changes
- Path canonicalization (file traversal fixes)
- Parameterized queries replacing concatenation
- Deserialization filters or whitelists
- Resource limits (size, timeout, rate)

**Context clues**:

- New security library imports
- Validation-related exceptions
- Early return statements (validation gates)
- Generic error messages (info disclosure fix)

### 4. Analyze Each Security Change

For each finding:

- What changed: Describe modification
- Vulnerability type: CWE classification if known
- Attack scenario: How was it exploitable?
- Fix effectiveness: Does it fully mitigate?
- Proof of concept: Exploitation example if possible

## Report Format

```markdown
# Patch Analysis: [Application/CVE]

## Executive Summary
[1-2 sentences: what was fixed]

## Identified Vulnerabilities

### 1. [Vuln Type] in [File:Lines]

**Severity**: Critical/High/Medium/Low

**Vulnerable Code**:
[Before - what was exploitable]

**Fixed Code**:
[After - what changed]

**Attack Scenario**:
[How to exploit - be specific]

**Proof of Concept**:
[Concrete example if possible]

**Completeness**: [Is fix complete? Any bypasses?]

### 2. [Next Vulnerability...]

## Non-Security Changes
[Brief mention of refactoring/features]

## Additional Recommendations
1. [Further hardening suggestions]
2. [Related areas to review]
```

## Special Cases

- **Decompilation fails**: Try alternative decompiler or analyze bytecode directly
- **Large diffs (100+ files)**: Focus on security-sensitive areas (auth, input handling, file I/O)
- **Obfuscated code**: Note limitations, focus on logical intent
- **No CVE provided**: Analyze all changes, categorize security relevance

## Critical Reminders

- **Context**: Always use `cd` before bash commands since execution resets to current dir
- **Paths**: Provide full/relative paths when not using `cd`
- **Read everything**: Don't skip changes, pattern-match, or use grep on diffs
- **Authorization**: Ensure proper authorization before analyzing any software
- **Proprietary focus**: Third-party updates are expected; proprietary changes reveal custom vulnerabilities