# Example Patch Analysis Workflow

This document shows a complete example of using the patch-diff-analyzer extension.

## Scenario

You have two JAR files:
- `myapp-1.2.3.jar` (vulnerable version)
- `myapp-1.2.4.jar` (patched version)

You want to understand what security vulnerability was fixed.

## Step-by-Step Example

### User Request
```
I have myapp-1.2.3.jar and myapp-1.2.4.jar. Can you analyze what
security changes were made between these versions?
```

### Hacktron's Response Flow

#### 1. Identification Phase
```
I'll analyze these JAR files for security changes. Based on the version
numbers, myapp-1.2.4.jar is likely the patched version (higher version).

Let me set up the analysis workspace and decompile both versions.
```

#### 2. Setup Workspace
```bash
./scripts/setup-workspace.sh myapp-analysis
```

#### 3. Decompile Unpatched Version
```bash
./scripts/decompile-jar.sh myapp-1.2.3.jar myapp-analysis/decompiled/
cd myapp-analysis
git add -A
git commit -m "Unpatched version 1.2.3"
git tag unpatched
```

Output:
```
====================================
JAR Decompilation Script
====================================
Input JAR: myapp-1.2.3.jar
Output Dir: myapp-analysis/decompiled/

Using jadx decompiler
Decompiling...

✓ Decompilation successful!
Output directory: myapp-analysis/decompiled/
Java files extracted: 247
```

#### 4. Decompile Patched Version
```bash
rm -rf myapp-analysis/decompiled/*
./scripts/decompile-jar.sh myapp-1.2.4.jar myapp-analysis/decompiled/
cd myapp-analysis
git add -A
git commit -m "Patched version 1.2.4"
git tag patched
```

#### 5. Generate Diff
```bash
./scripts/analyze-diff.sh myapp-analysis/
```

Output:
```
====================================
Patch Diff Analysis
====================================
Workspace: myapp-analysis

Commit History:
a1b2c3d (HEAD -> main, tag: patched) Patched version 1.2.4
d4e5f6g (tag: unpatched) Unpatched version 1.2.3

Using tagged references: unpatched -> patched

====================================
Diff Statistics
====================================
 com/example/app/FileHandler.java    | 15 ++++++++++----
 com/example/app/UploadServlet.java  |  8 ++++++--
 2 files changed, 17 insertions(+), 6 deletions(-)

====================================
Changed Files
====================================
M	com/example/app/FileHandler.java
M	com/example/app/UploadServlet.java

====================================
Generating Detailed Diff
====================================
✓ Diff generated: patch-analysis.diff
  Total lines: 52
```

#### 6. LLM Analysis of Diff

Hacktron reads `patch-analysis.diff`:

```diff
diff --git a/com/example/app/FileHandler.java b/com/example/app/FileHandler.java
index abc123..def456 100644
--- a/com/example/app/FileHandler.java
+++ b/com/example/app/FileHandler.java
@@ -45,10 +45,17 @@ public class FileHandler {
     }

     public File getFile(String filename) throws IOException {
-        File file = new File(uploadDir, filename);
+        // Validate filename to prevent path traversal
+        if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
+            throw new SecurityException("Invalid filename: " + filename);
+        }
+
+        File file = new File(uploadDir, filename);
+        String canonicalPath = file.getCanonicalPath();

-        if (!file.exists()) {
-            throw new FileNotFoundException("File not found");
+        // Ensure file is within upload directory
+        if (!canonicalPath.startsWith(uploadDir.getCanonicalPath())) {
+            throw new SecurityException("Access denied");
         }

         return file;
```

### Hacktron's Security Analysis

```
## Analysis Summary

I've identified a **path traversal vulnerability fix** between versions 1.2.3 and 1.2.4.

## Vulnerability Details

**Affected File**: com/example/app/FileHandler.java:48-58

**Vulnerability Type**: Path Traversal (CWE-22)

### Vulnerable Code (1.2.3)
The original code directly constructed file paths from user input without validation:
```java
public File getFile(String filename) throws IOException {
    File file = new File(uploadDir, filename);
    if (!file.exists()) {
        throw new FileNotFoundException("File not found");
    }
    return file;
}
```

### Security Issue
An attacker could provide filenames like:
- `../../../etc/passwd`
- `..\\..\\windows\\system32\\config\\sam`

This would allow reading arbitrary files outside the intended upload directory.

### Patched Code (1.2.4)
The fix implements two layers of defense:

1. **Input Validation**: Rejects filenames containing path traversal sequences
```java
if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
    throw new SecurityException("Invalid filename: " + filename);
}
```

2. **Canonical Path Verification**: Ensures the resolved path stays within bounds
```java
String canonicalPath = file.getCanonicalPath();
if (!canonicalPath.startsWith(uploadDir.getCanonicalPath())) {
    throw new SecurityException("Access denied");
}
```

## Severity Assessment

**Critical** - This vulnerability could allow:
- Reading sensitive system files
- Accessing other users' uploaded files
- Information disclosure
- Potential for further exploitation

## Additional Changes

**File**: com/example/app/UploadServlet.java:112-119

Minor changes to error handling (logging the security exceptions), but the
core fix is in FileHandler.java.

## Confidence Level

**High (95%)** - The changes clearly address path traversal with standard
mitigation techniques.

## Recommendations

1. ✓ The fix properly addresses the vulnerability
2. ✓ Both blacklist (input validation) and whitelist (canonical path check) are used
3. Consider: Add logging/monitoring for SecurityException occurrences
4. Consider: Rate limiting on file access attempts
```

## Key Takeaways

This example demonstrates:

1. **Automatic version detection** from filenames
2. **Clean git-based workflow** for diffing
3. **Focused LLM analysis** on security-relevant changes
4. **Contextual reasoning** about vulnerability type and impact
5. **Code references** with file:line notation
6. **Confidence assessment** of the analysis

## Variations

### With CVE Context

If the user had provided:
```
Analyze these JARs. CVE-2024-1234 mentions a path traversal
in the file upload feature.
```

Hacktron would:
- Immediately focus on file/path-related changes
- Verify the fix addresses the CVE description
- Assess completeness of the patch

### Blind Analysis (No Context)

Without any hints, Hacktron would:
- Analyze all changes
- Categorize security vs non-security changes
- Provide multiple hypotheses if unclear
- Rate confidence for each finding
