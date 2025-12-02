# Patch Diff Analyzer

**IMPORTANT**: Users may request analysis of security patches in compiled binaries (JARs, DLLs, etc.) to understand what vulnerabilities were fixed. This extension helps decompile binaries, generate diffs, and identify security-relevant changes.

---

## Workflow Decision Tree

When a user requests patch analysis:

1. **Identifying Binaries**: Do you need to determine which file is patched vs unpatched?
   - **YES** → Go to [Binary Identification](#binary-identification)
   - **NO** → User has specified versions, proceed to [Setup & Decompilation](#setup--decompilation)

2. **File Format**: What type of binary are you analyzing?
   - **Java JAR** → Use [JAR Decompilation Workflow](#jar-decompilation-workflow)
   - **.NET DLL/EXE** → Use [.NET Decompilation Workflow](#net-decompilation-workflow)
   - **Other** → Consult user for appropriate decompiler

3. **Analysis Context**: Does the user provide vulnerability information?
   - **YES (CVE/Description provided)** → Focus analysis on related changes
   - **NO (Blind analysis)** → Perform comprehensive security change analysis

---

## Binary Identification

**CRITICAL**: Before decompilation, correctly identify which binary is the patched version.

### Identification Methods

1. **Explicit Naming**:
   - Files named `patched.jar` / `unpatched.jar`
   - Files named `vulnerable.jar` / `fixed.jar`
   - → Use as specified

2. **Version Numbers**:
   - `app-1.2.3.jar` vs `app-1.2.4.jar`
   - → Higher version number is typically patched (1.2.4 > 1.2.3)
   - For semantic versioning: major.minor.patch format

3. **File Timestamps**:
   ```bash
   ls -lt *.jar
   ```
   - Newer timestamp typically indicates patched version
   - **Note**: Not reliable if files were copied/moved

4. **When Ambiguous**:
   - **ALWAYS** ask the user for clarification
   - Do not guess if there's any uncertainty

### Example
```
User provides: myapp-old.jar and myapp-new.jar
→ "new" clearly indicates the patched version
```

---

## Setup & Decompilation

### Prerequisites Check

**MANDATORY**: Before starting, verify required tools are installed.

#### For Java JARs
At least one of these decompilers must be available:
- `jadx` (recommended): `brew install jadx`
- `jd-cli`: `brew install jd-cli`
- `cfr`: Download from https://www.benf.org/other/cfr/

Check availability:
```bash
command -v jadx || command -v jd-cli || command -v cfr
```

#### For .NET DLLs
- `ilspycmd` (recommended): `dotnet tool install -g ilspycmd`
- `monodis` (fallback): `brew install mono`

Check availability:
```bash
command -v ilspycmd || command -v dotnet || command -v monodis
```

### Workspace Setup Script

Use the provided setup script:

```bash
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/setup-workspace.sh <workspace-name>
```

**What it does**:
1. Creates workspace directory
2. Initializes git repository for diff tracking
3. Configures git user for commits
4. Creates subdirectories: `decompiled/`, `output/`

**Output**:
```
✓ Git repository initialized
✓ Workspace structure created
Workspace ready at: /path/to/workspace-name
```

---

## Efficient Extraction (Skip Third-Party Libraries)

**CRITICAL**: For WAR files or large applications, extract ONLY proprietary code before decompiling. This saves significant time and storage.

### Identify Proprietary Code Location

**WAR file structure**:
```
application.war
├── WEB-INF/
│   ├── classes/          ← Application code (DECOMPILE THIS)
│   │   └── com/
│   │       └── vendor/   ← Proprietary packages
│   └── lib/              ← Third-party JARs (SKIP THESE)
│       ├── jackson-*.jar
│       ├── spring-*.jar
│       └── hibernate-*.jar
└── META-INF/
```

### Extract Proprietary Code Only

```bash
# 1. List WAR contents to identify proprietary packages
unzip -l unpatched.war | grep "WEB-INF/classes" | grep "\.class$" | head -30

# Look for company-specific packages:
# WEB-INF/classes/com/acme/
# WEB-INF/classes/com/vendor/
# WEB-INF/classes/org/internal/

# 2. Extract ONLY proprietary classes
mkdir -p temp-unpatched
unzip unpatched.war "WEB-INF/classes/com/vendor/*" -d temp-unpatched/
unzip unpatched.war "WEB-INF/classes/com/acme/*" -d temp-unpatched/

# 3. Create JAR from extracted classes
cd temp-unpatched/WEB-INF/classes
jar cf ../../../vendor-unpatched.jar .
cd ../../..

# 4. Repeat for patched version
mkdir -p temp-patched
unzip patched.war "WEB-INF/classes/com/vendor/*" -d temp-patched/
unzip patched.war "WEB-INF/classes/com/acme/*" -d temp-patched/
cd temp-patched/WEB-INF/classes
jar cf ../../../vendor-patched.jar .
cd ../../..

# Now decompile ONLY proprietary code (much faster!)
```

---

## JAR Decompilation Workflow

### Step 1: Decompile Unpatched Version (Proprietary Code)

```bash
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/decompile-jar.sh \
  <unpatched.jar> \
  <workspace>/decompiled/
```

**What the script does**:
- Automatically detects available decompiler (jadx, jd-cli, or cfr)
- Decompiles JAR to Java source files
- Outputs statistics (file count, directory structure)

**Expected output**:
```
Using jadx decompiler
Decompiling...
✓ Decompilation successful!
Java files extracted: 247
```

### Step 2: Commit Unpatched Version

```bash
cd <workspace>
git add -A
git commit -m "Unpatched version"
git tag unpatched
```

**CRITICAL**: The `unpatched` tag is used by the diff analysis script.

### Step 3: Decompile Patched Version

**IMPORTANT**: Clear the decompiled directory first to avoid mixing files.

```bash
rm -rf <workspace>/decompiled/*
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/decompile-jar.sh \
  <patched.jar> \
  <workspace>/decompiled/
```

### Step 4: Commit Patched Version

```bash
cd <workspace>
git add -A
git commit -m "Patched version"
git tag patched
```

**CRITICAL**: The `patched` tag is used by the diff analysis script.

---

## .NET Decompilation Workflow

### Step 1: Decompile Unpatched Version

```bash
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/decompile-dll.sh \
  <unpatched.dll> \
  <workspace>/decompiled/
```

**What the script does**:
- Automatically detects available decompiler (ilspycmd or monodis)
- Decompiles DLL/EXE to C# source files (or IL if only monodis available)
- Outputs statistics

**Note**: If only `monodis` is available, output will be IL assembly code rather than C# source. IL is still analyzable but less readable.

### Step 2-4: Same as JAR Workflow

Follow the same git commit process as the JAR workflow:
1. Commit unpatched with tag
2. Clear directory
3. Decompile patched
4. Commit patched with tag

---

## Diff Generation & Analysis

### Generate Diff

```bash
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/analyze-diff.sh <workspace>
```

**What the script does**:
1. Verifies git repository has 2+ commits
2. Identifies `unpatched` and `patched` tags (or uses HEAD~1 and HEAD)
3. Generates diff statistics
4. Creates `patch-analysis.diff` file
5. Creates `changed-files.txt` list

**Expected output**:
```
Diff Statistics
 FileHandler.java    | 15 ++++++++++----
 UploadServlet.java  |  8 ++++++--
 2 files changed, 17 insertions(+), 6 deletions(-)

✓ Diff generated: patch-analysis.diff
  Total lines: 52
```

### Read and Analyze Diff

**MANDATORY**: Read the generated diff file completely.

```bash
# Read the complete diff
Read patch-analysis.diff

# Read the list of changed files
Read changed-files.txt
```

**DO NOT** use grep or pattern matching. The LLM must read and reason about the actual code changes.

---

## Security Analysis

**CRITICAL**: This is where you apply security expertise to understand the vulnerability fix.

### Step 1: Filter Third-Party Libraries

**MANDATORY FIRST STEP**: Before analyzing changes, separate proprietary code from third-party libraries.

**Why This Matters**:
- Third-party library updates are expected and well-documented (Jackson, Spring, Hibernate, etc.)
- Proprietary code changes indicate application-specific security fixes
- Custom vulnerabilities are more interesting than known library CVEs
- Focusing on proprietary code reveals unique attack vectors

**How to Filter**:

1. **Identify Package Namespaces**:
   ```bash
   # Review changed files to identify patterns
   cat changed-files.txt | head -100

   # Common third-party prefixes to ignore:
   # - com.fasterxml.jackson.*     (Jackson JSON)
   # - org.springframework.*       (Spring Framework)
   # - org.hibernate.*             (Hibernate ORM)
   # - org.apache.*                (Apache Commons, etc.)
   # - com.google.*                (Google libraries)
   # - io.netty.*                  (Netty)
   # - javax.*, jakarta.*          (Java EE specs)
   # - org.slf4j.*, ch.qos.logback.* (Logging)
   # - com.ctc.wstx.*              (Woodstox XML)
   ```

2. **Extract Proprietary Code Changes**:
   ```bash
   # Filter out third-party libraries to find proprietary code
   grep "^decompiled/sources/" changed-files.txt | \
     grep -v "^decompiled/sources/com/fasterxml" | \
     grep -v "^decompiled/sources/org/springframework" | \
     grep -v "^decompiled/sources/org/hibernate" | \
     grep -v "^decompiled/sources/org/apache" | \
     grep -v "^decompiled/sources/com/google" | \
     grep -v "^decompiled/sources/io/netty" | \
     grep -v "^decompiled/sources/javax" | \
     grep -v "^decompiled/sources/jakarta"
   ```

3. **Identify Proprietary Namespace**:
   - Look for company-specific package names
   - Examples: `com.acme.*`, `com.example.*`, `com.companyname.*`
   - Internal packages often lack open-source prefixes
   - May use domain-based naming: `com.vendor.*`, `com.product.*`

4. **Count and Report Both**:
   ```bash
   # Count total changes
   wc -l changed-files.txt

   # Count proprietary changes
   grep "com/proprietary/namespace" changed-files.txt | wc -l
   ```

**Example Analysis Statement**:
```
Total changes: 2,626 files

Third-party library updates:
- Jackson Databind: 400+ files (known CVE fixes)
- Woodstox XML: 150+ files (XXE/XML bomb protection)
- Hibernate Validator: 100+ files (API changes)

Proprietary code changes: 73 files
- Package namespace: com.acme.*, com.vendor.*
- Focus analysis on these proprietary changes
```

**After Filtering**: Proceed with detailed analysis of proprietary code only, unless user specifically requests third-party analysis.

---

### Step 2: Analysis Process

1. **Read Every Change**: Don't skip any modifications, even small ones
2. **Understand Context**: Look at surrounding code, not just the diff lines
3. **Identify Security Changes**: Distinguish security fixes from refactoring/features
4. **Reason About Vulnerability**: What attack was possible before? What does the fix prevent?
5. **Assess Completeness**: Is the fix comprehensive or could there be bypasses?

### What to Look For

**High-Priority Indicators**:
- Input validation added where none existed
- Sanitization/encoding of user-controlled data
- Authentication/authorization checks introduced
- Bounds checking before array/buffer access
- Type checking or casting changes
- Canonicalization of file paths
- Parameterized queries replacing string concatenation
- Deserialization filters or whitelists
- Resource limits (size, timeout, rate)

**Context Clues**:
- New imports of security libraries
- Exception handling for security conditions
- Early return statements (validation gates)
- Method signatures gaining validation parameters
- Error messages becoming more generic (info disclosure fix)

**Medium-Priority**:
- Configuration defaults changing to more secure values
- Cryptographic algorithm/key size upgrades
- Logging additions (may indicate security monitoring)
- Timeout/resource limit adjustments

### Reasoning Framework

For each significant change, document:

1. **What changed**: Describe the code modification
2. **Security implication**: What vulnerability this addresses
3. **Attack scenario**: How could an attacker have exploited the vulnerable version?
4. **Fix effectiveness**: Does this fully mitigate the vulnerability?
5. **Confidence level**: How certain are you about this analysis?

### Example Analysis Format

```
## File: com/example/FileHandler.java:48-58

### Change Description
Added input validation and canonical path checking to getFile() method.

### Vulnerability: Path Traversal (CWE-22)

**Before (Vulnerable)**:
- Directly constructed file paths from user input
- No validation of `../` sequences
- Attacker could access arbitrary files: `getFile("../../../../etc/passwd")`

**After (Fixed)**:
- Validates filename doesn't contain traversal sequences
- Verifies canonical path stays within upload directory
- Both blacklist (input validation) and whitelist (path verification) defenses

### Confidence: HIGH (95%)
The fix follows standard path traversal mitigation patterns.
```

---

## Reporting Findings

### Report Structure

**MANDATORY**: Use this structure for your analysis report:

```markdown
# Patch Analysis Summary

## Overview
[Brief description of what was analyzed]

## Vulnerability Identified: [Type/CVE]

**Severity**: [Critical/High/Medium/Low]

## Detailed Analysis

### File: [path/to/file.java:line-range]

[Detailed analysis following the framework above]

### File: [another/file.java:line-range]

[Continue for each security-relevant change]

## Non-Security Changes

[Briefly mention refactoring, features, etc. that aren't security-related]

## Completeness Assessment

[Is the fix complete? Any potential bypasses? Additional recommendations?]

## Confidence Level

Overall confidence: [HIGH/MEDIUM/LOW] ([percentage]%)

[Explain reasoning for confidence level]

## Additional Recommendations

1. [If applicable, suggest further hardening]
2. [Monitoring/logging suggestions]
3. [Related areas to review]
```

### Code References

**IMPORTANT**: Always include file paths and line numbers.

Format: `path/to/File.java:123-145`

This allows users to quickly locate the relevant code.

---

## Special Cases & Troubleshooting

### Decompilation Failures

**If decompilation fails**:
1. Try alternative decompiler: The scripts auto-detect, but you can install others
2. Check if binary is corrupted: Verify file integrity
3. Handle obfuscation: Note if code is heavily obfuscated and analysis may be limited
4. Bytecode analysis: For critical methods, can analyze raw bytecode if needed

**If decompiled code has errors**:
- Decompilers may produce invalid Java/C# for complex bytecode
- Focus on the logical intent, not syntactic perfection
- Note where decompilation quality is poor

### Large Diffs

**If diff is too large** (hundreds of files changed):
1. Start with changed-files.txt to identify likely candidates
2. Focus on files in security-sensitive areas (auth, input handling, file I/O)
3. Analyze in batches, asking user to confirm priority areas
4. Look for patterns across multiple files

### Ambiguous Changes

**If security relevance is unclear**:
- Present multiple interpretations
- Rate confidence for each hypothesis
- Explain what additional context would help
- Recommend asking the vendor/security team

### Missing Context

**If analyzing blind** (no CVE/description):
- Analyze all changes systematically
- Categorize: definitely security / possibly security / non-security
- For "possibly security", explain your reasoning and uncertainty
- Don't overstate conclusions

---

## Best Practices

1. **Verify Before Analyzing**: Always check decompilation completed successfully
2. **Read, Don't Pattern Match**: Understand the code logic, don't just grep for keywords
3. **Full Context Matters**: Review surrounding code and entire methods
4. **Multiple Changes May Be Related**: A fix might span several files/methods
5. **Dependencies Count**: Check if library versions changed (pom.xml, packages.config)
6. **Test Your Hypothesis**: If possible, explain how to reproduce/verify the vulnerability
7. **Document Assumptions**: Be clear about what you know vs. what you're inferring
8. **Confidence Levels**: Always provide confidence assessment for your conclusions

---

## Error Messages & Solutions

### "No decompiler found"
**Solution**: Install a decompiler (see [Prerequisites Check](#prerequisites-check))

### "Not a git repository"
**Solution**: Run `setup-workspace.sh` script first

### "Need at least 2 commits"
**Solution**: Ensure both unpatched and patched versions were committed

### "No differences found"
**Solution**:
- Verify you decompiled different versions
- Check `git log` to see commits
- May indicate files are identical

### "Decompilation failed"
**Possible causes**:
- Corrupted binary file
- Unsupported file format
- Decompiler bug
- Insufficient memory

**Solution**: Try alternative decompiler or analyze at bytecode level

---

## Security & Ethics

**CRITICAL**: This extension is intended for:
- ✓ Authorized security research
- ✓ Analyzing your own software
- ✓ CTF challenges and educational purposes
- ✓ Defensive security work
- ✓ Vulnerability disclosure research

**NOT for**:
- ✗ Analyzing software without authorization
- ✗ Reverse engineering for malicious purposes
- ✗ Violating license agreements or copyright
- ✗ Circumventing security for unauthorized access

Always ensure you have proper authorization before analyzing any software.

---

## Quick Reference

### Full Workflow Commands

```bash
# 1. Setup workspace
extension_script ~/.hacktron/extensions/patch-diff-analyzerripts/setup-workspace.sh myanalysis

# 2. Decompile unpatched
extension_script ~/.hacktron/extensions/patch-diff-analyzerripts/decompile-jar.sh unpatched.jar myanalysis/decompiled/

# 3. Commit unpatched
cd myanalysis
git add -A && git commit -m "Unpatched version" && git tag unpatched

# 4. Decompile patched
rm -rf decompiled/*
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/decompile-jar.sh ../patched.jar decompiled/

# 5. Commit patched
git add -A && git commit -m "Patched version" && git tag patched

# 6. Generate diff
extension_script ~/.hacktron/extensions/patch-diff-analyzer/scripts/analyze-diff.sh .

# 7. Analyze (read patch-analysis.diff and apply expertise)
```

---

Now proceed with the user's patch analysis request!