# Patch Diff Analyzer

A Hacktron extension for analyzing security patches by comparing vulnerable and patched versions of applications. Automatically decompiles binaries, generates diffs, and identifies security vulnerabilities that were fixed.

## What It Does

This extension helps security researchers and developers understand what vulnerabilities were fixed in software patches by:

- **Decompiling** binary files (JAR, DLL, WAR) to source code
- **Comparing** unpatched vs patched versions using git diffs
- **Identifying** security-relevant changes (input validation, auth fixes, path traversal, etc.)
- **Generating** structured security analysis reports

## Use Cases

- Analyze security patches when CVE details are vague
- Understand what vulnerabilities were fixed in application updates
- Review patch completeness and identify potential bypasses
- Learn from security fixes in third-party software

## Quick Start

### For Binary Files (JAR/DLL)

**For small files (< 20MB):**
```bash
# 1. Set up analysis workspace
./scripts/setup-workspace.sh myanalysis

# 2. Decompile unpatched version
./scripts/decompile-jar.sh ./unpatched.jar ./myanalysis/decompiled/
cd ./myanalysis && git add -A && git commit -m "Unpatched" && git tag unpatched

# 3. Decompile patched version
rm -rf ./myanalysis/decompiled/*
./scripts/decompile-jar.sh ./patched.jar ./myanalysis/decompiled/
cd ./myanalysis && git add -A && git commit -m "Patched" && git tag patched

# 4. Generate diff and analyze
./scripts/analyze-diff.sh ./myanalysis
```

**For large files (recommended):**
```bash
# 1. Set up analysis workspace
./scripts/setup-workspace.sh myanalysis

# 2. Scan binary to identify proprietary packages
./scripts/scan-binary.sh ./unpatched.jar

# 3. Decompile only proprietary packages (one by one)
mkdir -p ./myanalysis/decompiled
./scripts/decompile-jar.sh ./unpatched.jar ./myanalysis/decompiled/ com.example.app
./scripts/decompile-jar.sh ./unpatched.jar ./myanalysis/decompiled/ com.example.util
# ... continue for each proprietary package from scan output

cd ./myanalysis && git add -A && git commit -m "Unpatched" && git tag unpatched

# 4. Decompile patched version (same packages)
rm -rf ./myanalysis/decompiled/*
./scripts/decompile-jar.sh ./patched.jar ./myanalysis/decompiled/ com.example.app
./scripts/decompile-jar.sh ./patched.jar ./myanalysis/decompiled/ com.example.util
# ... use same packages as step 3

cd ./myanalysis && git add -A && git commit -m "Patched" && git tag patched

# 5. Generate diff and analyze
./scripts/analyze-diff.sh ./myanalysis
```

### For Existing Git Repository

If you already have a git repo with version tags:

```bash
./scripts/analyze-diff.sh .
```

## Prerequisites

- **Java JARs**: Requires `jadx`, `jd-cli`, or `cfr` decompiler
- **.NET DLLs**: Requires `ilspycmd` or `monodis`
- **Git**: For version control and diffing

Check availability: `command -v jadx || command -v jd-cli`

## Output

The analysis generates:

- `patch-analysis.diff` - Complete diff between versions
- `changed-files.txt` - List of modified files
- **Security Analysis Report** - Structured report with:
  - Executive summary
  - Identified vulnerabilities (severity, attack scenarios, PoC)
  - Non-security changes
  - Recommendations

## Report Format

Reports follow a standard structure:

- **Executive Summary**: Brief overview of what was fixed
- **Identified Vulnerabilities**: Detailed analysis per vulnerability
  - Severity rating
  - Vulnerable vs fixed code
  - Attack scenarios and proof of concept
  - Completeness assessment
- **Non-Security Changes**: Refactoring and feature updates
- **Additional Recommendations**: Further hardening suggestions

## Documentation

- **[USAGE.md](USAGE.md)** - Detailed technical guide for LLM agents (workflows, analysis process)
- **[examples/example-workflow.md](examples/example-workflow.md)** - Complete step-by-step example with real scenario

## Tips

- **Large WAR/JAR files**: Always use `scan-binary.sh` first to identify proprietary packages, then decompile only those packages using the filter parameter. This can reduce decompilation time from hours to minutes.
- **Version identification**: When unclear which file is patched, check version numbers, filenames, or ask
- **Focus on proprietary code**: Third-party library updates are expected; custom code changes reveal the actual vulnerabilities
- **Performance**: For files > 20MB or with 1000+ classes, the scan + filter approach is essential for reasonable analysis time

## Contributing

This extension has scope for expansion in several areas:

### Additional Binary Support

Currently supports Java JARs/WARs and .NET DLLs. Potential additions:

- **Python**: `.pyc` bytecode decompilation (uncompyle6, decompyle3)
- **Go**: Binary analysis tools (ghidra, IDA Pro integration)
- **Rust**: Binary analysis and symbol recovery
- **Native binaries**: ELF/PE analysis with Ghidra or IDA Pro
- **Android**: APK analysis (already partially covered via JAR tools)

### Enhanced LLM Instructions

Improve analysis quality by expanding:

- **Vulnerability patterns**: Add more CWE-specific detection patterns to USAGE.md
- **Context clues**: Expand the list of security indicators (imports, exceptions, patterns)
- **Report templates**: Add specialized templates for different vulnerability types
- **False positive reduction**: Better guidance on distinguishing security fixes from refactoring

### Tool Integration

- Support for additional decompilers and their specific options
- Integration with security scanners (SAST tools) for cross-validation
- Automated CVE correlation when analyzing known CVEs

### Script Improvements

- Better error handling and user feedback
- Progress indicators for long-running decompilation
- Support for parallel decompilation of multiple files
- Automatic third-party library filtering improvements

Contributions welcome! Please see the existing scripts in `scripts/` and documentation in `USAGE.md` for implementation patterns.
