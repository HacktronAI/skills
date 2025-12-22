---
name: js-audit-helper
description: >
  Prepares minified JavaScript files for auditing by unminifying
  and splitting them into manageable chunks, providing index files and static security report
  for better understanding, than plain minified files.
compatibility: Requires python installed along with jsbeautifier and tree-sitter dependencies
metadata:
  name: "js-audit-helper"
  version: "0.0.1"
  author: "@hacktron"
  tags:
    - "audit js"
    - "unminify"
    - "js analysis"
---

# JS Audit Helper - Extension Usage Guide

## Purpose
Unminifies and semantically splits JavaScript files into manageable chunks for security auditing. Generates automated pattern-based reports and structure maps to accelerate manual analysis.

## When to Use
- File is minified (single-line, no formatting)
- File >500 lines of JavaScript
- User requests JS security audit or code review

Skip if file is well-formatted AND <300 lines.

## Execution

```bash
# Single file
audit_prep.py target.js

# Directory (recursive)
audit_prep.py ./js_folder

# Output location
./audit_workspace/
```

## What It Does
1. Beautifies minified code (adds formatting)
2. Splits at function/class boundaries (~15K chars per chunk)
3. Pattern-matches security indicators (regex-based)
4. Generates `_SECURITY_REPORT.json` with potential findings
5. Creates `_structure.json` mapping all functions/classes to chunks
6. Outputs numbered chunks with security annotations in headers

## Post-Execution Workflow

### Step 1: Read Static Analysis Report
```bash
read_file ./audit_workspace/<filename_without_extension>/_SECURITY_REPORT.json
```

**CRITICAL UNDERSTANDING**: This is a **pattern-matching report**, NOT confirmed vulnerabilities. Most findings are false positives. Your job is validation. Don't fully depend on the static report, just use it as a starting point, and explore the codebase to understand and find more vulnerabilities in the process.

**Report contains:**
- `total_findings`: Count of pattern matches (NOT confirmed vulns)
- `findings_summary`: Categories (secrets, dom_xss, user_input, redirects, network)
- `critical_findings`: High-priority patterns with line numbers and chunk files
- `hotspots`: Context-aware suspicious patterns (function names included)
- `chunks_with_findings`: Which chunks contain matches

**Use report to:**
1. Identify patterns worth investigating (prioritize `critical_findings`)
2. See which chunks need review (`chunks_with_findings`)
3. Get line numbers for grep searches
4. Understand code structure from `hotspots` context

### Step 2: Never Trust, Always Verify

**VALIDATION IS MANDATORY** - The script uses regex patterns that flag:
- Test/example secrets as "hardcoded credentials"
- Static `.innerHTML` as "XSS vulnerabilities"
- Localhost URLs as "insecure connections"
- User input sources without checking if they reach dangerous sinks

**Professional auditor mindset:**
- Pattern match = "investigate this location"
- NOT pattern match = "confirmed vulnerability"
- Trace data flows from source to sink
- Check for sanitization between input and output
- Understand business logic context

### Step 3: Use grep as Your Primary Tool

**DON'T guess chunk numbers or read files blindly. Use grep.**

**Find where functions are defined:**
```bash
grep -n "function handleAuth\|const handleAuth" audit_workspace/<folder>/*.js
```

**Find where variables are used:**
```bash
grep -n "apiKey" audit_workspace/<folder>/*.js
```

**Query structure map (DO NOT read entire file):**
```bash
# Find specific function location
grep -A 2 '"name": "validateUser"' audit_workspace/<folder>/_structure.json

# Find methods in a class
grep -A 2 '"parent": "AuthHandler"' audit_workspace/<folder>/_structure.json

# Find what's defined at line range
grep -B 1 -A 2 '"line": 450' audit_workspace/<folder>/_structure.json
```

**Find all instances of a pattern:**
```bash
grep -r "location\.hash\|location\.search" audit_workspace/<folder>/
grep -r "innerHTML\|outerHTML" audit_workspace/<folder>/
```

**Structure map format:**
```json
{
  "type": "function",
  "name": "processInput",
  "line": 1250,
  "end_line": 1280,
  "parent": "DataHandler",
  "chunk_file": "main_part_004.js",
  "chunk_number": 4
}
```

### Step 4: Data Flow Validation (Core Skill)

**For every flagged pattern, trace the complete data flow:**

**Example: innerHTML XSS validation**
1. Report flags: `div.innerHTML = msg` at line 456 in chunk 7
2. Read that chunk: `read_file audit_workspace/app/app_part_007.js`
3. Find where `msg` comes from (trace backward)
4. Check if sanitization exists between source and sink
5. Grep for the function if it's defined elsewhere

**Source → Sanitization → Sink analysis:**
```javascript
// Source (user-controlled?)
const input = location.hash.substring(1);  // User input

// Sanitization? (present or absent?)
const clean = DOMPurify.sanitize(input);   // Sanitized

// Sink (dangerous operation?)
div.innerHTML = clean;                      // Safe (sanitized)

// VS

div.innerHTML = input;                      // Vulnerable (no sanitization)
```

**Common sources:** `location.*`, `document.cookie`, `localStorage`, URL params, API responses (check origin)

**Common sinks:** `.innerHTML`, `.outerHTML`, `eval()`, `document.write()`, `location.href =`, SQL queries

### Step 5: Pattern-by-Pattern Validation Rules

**Secrets (category: secrets)**
- FALSE POSITIVE: "your-api-key", "test", "example", "xxx", "mock"
- FALSE POSITIVE: Wrapped in `if (NODE_ENV === 'development')`
- TRUE POSITIVE: Real format (AWS: `AKIA...`, Stripe: `sk_live_...`, JWT: `eyJ...`)
- Validation: Check if production key vs placeholder

**DOM XSS (category: dom_xss)**
- FALSE POSITIVE: `.innerHTML = "static string"`
- FALSE POSITIVE: `.innerHTML = DOMPurify.sanitize(input)`
- FALSE POSITIVE: `.textContent = input` (textContent is safe)
- TRUE POSITIVE: `.innerHTML = location.hash` (user input → sink)
- Validation: Trace data flow, check sanitization

**User Input (category: user_input)**
- NOT A VULNERABILITY by itself - just marks potential taint sources
- Must trace where this input flows
- Only flag if reaches dangerous sink without sanitization

**Redirects (category: redirects)**
- FALSE POSITIVE: `location.href = "/hardcoded/path"`
- FALSE POSITIVE: Whitelist validation present
- TRUE POSITIVE: `location.href = params.get('redirect')` (open redirect)
- Validation: Check URL validation/whitelist logic

**Network (category: network)**
- FALSE POSITIVE: `http://localhost` (dev environment)
- FALSE POSITIVE: Private IPs (192.168.x.x, 10.x.x.x)
- TRUE POSITIVE: Production domain over HTTP
- Validation: Check environment context

### Step 6: Professional Auditor Approach

**Priority 1 (15 min): Validate Critical Findings**
- Read chunks containing items from `critical_findings` array
- Trace data flows using grep
- Document confirmed vulnerabilities only

**Priority 2 (20 min): Investigate Hotspots**
- Focus on concerning contexts (auth, payment, user data)
- Use function names from `hotspots` to grep definitions
- Validate with data flow analysis

**Priority 3 (30 min): Manual Pattern Hunting**
Automated scans miss:
- Logic flaws (auth bypasses, authorization issues)
- Prototype pollution (missing `__proto__` checks)
- ReDoS (regex: `(a+)+$`)
- Timing attacks (string comparison without constant-time)
- Insecure randomness (`Math.random()` for tokens)
- Business logic vulnerabilities

**Manual grep searches:**
```bash
grep -r "role\|admin\|permissions" audit_workspace/<folder>/
grep -r "crypto\|encrypt\|hash" audit_workspace/<folder>/
grep -r "__proto__\|constructor\|prototype" audit_workspace/<folder>/
grep -r "Math.random" audit_workspace/<folder>/
```

**Priority 4 (remaining time): Deep Dive**
- Read non-flagged chunks for logic review
- Check authentication/authorization flows
- Review cryptographic implementations
- Analyze business logic vulnerabilities

## Efficient Analysis Strategy

1. **Read security report** - understand pattern matches
2. **Grep structure map** - find function locations (never read entire _structure.json)
3. **Grep code chunks** - search for patterns across all files
4. **Read targeted chunks** - only chunks with findings or grep matches
5. **Trace data flows** - connect sources to sinks
6. **Validate findings** - distinguish real vulns from false positives
7. **Hunt manually** - find what regex can't catch

## Critical Reminders

**DO:**
- Use grep extensively (primary tool for navigation)
- Validate every automated finding with data flow analysis
- Read chunk headers (show context and findings)
- Check `chunk_file` field in findings to locate code
- Use structure map with grep (never read entire file)
- Think about business logic beyond pattern matching

**DON'T:**
- Trust automated findings without validation
- Read entire _structure.json (use grep queries)
- Report localhost URLs as production issues
- Flag sanitized innerHTML as XSS
- Report test/example secrets as critical
- Guess chunk numbers (use grep or chunk_file field)
- Read all chunks sequentially (waste of time)

## Common False Positives to Skip

```javascript
// Skip these patterns:
const API_KEY = "YOUR_API_KEY_HERE";           // Placeholder
div.innerHTML = "Static content";              // No user input
fetch('http://localhost:3000');                // Dev environment
div.innerHTML = DOMPurify.sanitize(input);     // Sanitized
div.textContent = userInput;                   // textContent is safe
if (isDev) { token = "test"; }                 // Test environment
```

## Workflow Checklist

- [ ] Run script: `audit_prep.py <target>`
- [ ] Read `_SECURITY_REPORT.json` (understand it's pattern-based, not confirmed vulns)
- [ ] Grep structure map to find function locations (don't read entire file)
- [ ] Grep code for cross-chunk patterns and data flows
- [ ] Read chunks containing critical findings
- [ ] Validate each finding with data flow tracing
- [ ] Use grep for manual vulnerability hunting
- [ ] Document only confirmed vulnerabilities with validation reasoning

**Remember: You are the auditor. The tool provides hints. Your job is validation through data flow analysis and security expertise.**