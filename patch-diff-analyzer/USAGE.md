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
setup-workspace.sh myanalysis
```

Creates git repo with proper structure.

### 2. Scan Binary to Identify Proprietary Packages

**CRITICAL**: For large JARs/WARs/DLLs, always scan first to identify proprietary code. This dramatically reduces decompilation time by skipping third-party libraries.

```bash
# Scan unpatched binary to identify proprietary packages
scan-binary.sh ./unpatched.jar

# Example output:
# --- Top Level Java Packages (Frequency Count) ---
#    245 com.acme.app
#    128 com.acme.util
#     89 com.acme.security
#     12 com.example.service
```

**What to look for**:
- Packages with high frequency counts (most likely proprietary)
- Unique package names (not `org.*`, `com.google.*`, `org.springframework.*`, etc.)
- Company/organization-specific prefixes (e.g., `com.acme.*`, `com.yourcompany.*`)

**For .NET DLLs**: The scan shows namespace patterns. Focus on non-Microsoft namespaces.

### 3. Decompile Proprietary Packages Only

**MANDATORY for large files**: Use the filter parameter to decompile only proprietary packages one by one. This saves hours of decompilation time.

```bash
# Create output directory structure
mkdir -p ./myanalysis/decompiled

# Decompile each proprietary package separately
# Replace 'com.acme.app' with actual packages from scan output

# Package 1: com.acme.app
decompile-jar.sh \
  ./unpatched.jar ./myanalysis/decompiled com.acme.app

# Package 2: com.acme.util
decompile-jar.sh \
  ./unpatched.jar ./myanalysis/decompiled com.acme.util

# Package 3: com.acme.security
decompile-jar.sh \
  ./unpatched.jar ./myanalysis/decompiled com.acme.security

# Continue for all proprietary packages identified in scan
```

**Performance benefit**: Decompiling 3-5 proprietary packages (100-500 classes) takes minutes instead of hours for full JARs with thousands of third-party classes.

**Note**: The filter parameter supports:
- Standard JAR structure: `com/acme/app/*`
- Spring Boot JARs: `BOOT-INF/classes/com/acme/app/*`
- WAR files: `WEB-INF/classes/com/acme/app/*`

### 4. Commit Unpatched Version

After decompiling all proprietary packages:

```bash
cd ./myanalysis && 
git add -A && git commit -m "Unpatched version" && git tag unpatched
```

### 5. Scan and Decompile Patched Version

**IMPORTANT**: Use the same proprietary packages identified from the unpatched scan. If unsure, scan the patched version too:

```bash
# Optional: Scan patched version to verify packages (should be similar)
scan-binary.sh ./patched.jar

# Decompile same proprietary packages from patched version
# Use the SAME packages as unpatched version for accurate diffing

rm -rf ./myanalysis/decompiled/*

# Decompile each proprietary package (same packages as step 3)
decompile-jar.sh \
  ./patched.jar ./myanalysis/decompiled com.acme.app

decompile-jar.sh \
  ./patched.jar ./myanalysis/decompiled com.acme.util

decompile-jar.sh \
  ./patched.jar ./myanalysis/decompiled com.acme.security

# Continue for all proprietary packages
```

**For DLLs**: Use `decompile-dll.sh` (filter parameter not yet supported for DLLs, but scan-binary.sh helps identify namespaces to focus on).

### 6. Commit Patched

```bash
cd ./myanalysis && 
git add -A && git commit -m "Patched version" && git tag patched
```

## Workflow B: Existing Git Repo

If code is already in git with version tags:

```bash
analyze-diff.sh .
```

Script auto-detects unpatched/patched tags or uses last 2 commits.
## Generate Diff

```bash
analyze-diff.sh .
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

- **Large diffs (100+ files)**: Focus on security-sensitive areas (auth, input handling, file I/O). Use your tools efficiently to go through the patch file for security-sensitive areas if the diff is way too large.
- **Obfuscated code**: Note limitations, focus on logical intent
- **No CVE provided**: Analyze all changes, categorize security relevance

## Critical Reminders

- **Context**: Always use `cd` before bash commands since execution resets to current dir
- **Paths**: Provide full/relative paths when not using `cd`
- **Read everything**: Don't skip changes, pattern-match, or use grep on diffs
- **Authorization**: Ensure proper authorization before analyzing any software
- **Proprietary focus**: Third-party updates are expected; proprietary changes reveal custom vulnerabilities
- **Performance**: For JARs/WARs > 10MB or with 1000+ classes, ALWAYS use `scan-binary.sh` first, then decompile only proprietary packages using the filter parameter. This can reduce decompilation time from hours to minutes.