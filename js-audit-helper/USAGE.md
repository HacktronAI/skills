# JS Audit Helper - Extension Usage Guide

## Purpose
This extension unminifies and semantically splits JavaScript files into manageable chunks for security auditing. Minified code is too dense for effective analysis. This extension restructures it into semantically coherent parts with context markers and generates automated security reports.

## When to Use This extension

**ALWAYS use this extension when:**
- File is minified (single-line, no formatting)
- File is >500 lines of JavaScript
- User requests JS security audit or code review

**Skip this extension only if:**
- File is already well-formatted AND <300 lines
- File is not JavaScript

## Execution Command
```bash
extension_script ~/.hacktron/extensions/js-audit-helper/scripts/audit_prep.py 
```

**Examples:**
```bash
# Single file
extension_script ~/.hacktron/extensions/js-audit-helper/scripts/audit_prep.py app.min.js

# Entire directory
extension_script ~/.hacktron/extensions/js-audit-helper/scripts/audit_prep.py ./js_assets
```

**Output Location:** All results are saved to `audit_workspace/` directory.

## What the Script Does

1. **Unminifies** the JavaScript using jsbeautifier (adds indentation, newlines)
2. **Semantically splits** code at function/class boundaries (not arbitrary line counts)
3. **Scans for security patterns** automatically across all code
4. **Generates security report** (`_SECURITY_REPORT.json`) with findings and hotspots
5. **Creates chunks** (~15,000 chars each) with breadcrumb headers showing context
6. **Annotates chunks** with security findings found in that section

**Output Structure:**
```
audit_workspace/
  app/
    _SECURITY_REPORT.json  # Automated security scan results (READ THIS FIRST!)
    app_part_001.js        # First semantic chunk (may have security annotations)
    app_part_002.js        # Second semantic chunk
    ...
```

**Chunk Headers (Breadcrumbs):**
Each chunk starts with:
```javascript
// FILE: app.min.js | PART: 1/5
// CONTEXT: AuthHandler
// STARTING LINE: 245
//   SECURITY FINDINGS: 3
//    - API Key at line 250
//    - innerHTML assignment at line 267
//    - Location redirect at line 289
// ----------------------------------------
```

## CRITICAL: Post-Execution Workflow

### Step 0: ALWAYS Start with the Security Report
**DO THIS FIRST - before reading any code chunks:**
```bash
read_file audit_workspace//_SECURITY_REPORT.json
```

**This JSON file contains:**
- `total_findings`: Total number of security issues detected
- `findings_summary`: Breakdown by category (secrets, dom_xss, user_input, redirects, network)
- `critical_findings`: Array of HIGH PRIORITY issues (hardcoded secrets, DOM XSS patterns)
- `hotspots`: Context-aware dangerous code locations (e.g., "innerHTML in AuthHandler function")
- `chunks_with_findings`: List of chunk numbers that contain security issues (e.g., [1, 3, 7])

**Use this to:**
1. **Triage severity** - Focus on `critical_findings` first
2. **Prioritize chunks** - Only read chunks listed in `chunks_with_findings`
3. **Understand scope** - See total attack surface at a glance
4. **Plan investigation** - Use `hotspots` to identify dangerous code patterns in context

**Example Security Report Structure:**
```json
{
  "file": "app.min.js",
  "total_findings": 12,
  "findings_summary": {
    "secrets": 2,
    "dom_xss": 3,
    "user_input": 4,
    "redirects": 2,
    "network": 1
  },
  "critical_findings": [
    {
      "category": "secrets",
      "type": "API Key",
      "line": 250,
      "match": "apiKey = \"sk_live_abc123\"",
      "context": "const apiKey = \"sk_live_abc123\";"
    }
  ],
  "hotspots": [
    {
      "type": "Potential DOM XSS",
      "context": "renderProfile",
      "line": 456,
      "snippet": "profileDiv.innerHTML = getUserInput();"
    }
  ],
  "chunks_with_findings": [1, 3, 7, 9]
}
```

### Step 1: Investigate Critical Findings

**For each item in `critical_findings` array:**

1. **Note the line number** - e.g., line 250
2. **Calculate which chunk contains it:**
   - Each chunk ≈ 400 lines (varies due to semantic splitting)
   - Line 250 ÷ 400 ≈ chunk 1 (but check `chunks_with_findings` to confirm)
3. **Read that specific chunk:**
```bash
   read_file audit_workspace/app/app_part_001.js
```
4. **Validate the finding** (see Validation Rules below)

**DO NOT blindly trust automated findings** - the script uses regex patterns that may have false positives.

### Step 2: Analyze Hotspots

**Hotspots are context-aware findings** - they show WHERE dangerous operations occur:
```json
{
  "type": "Potential DOM XSS",
  "context": "renderUserProfile",  // Function name - gives semantic context
  "line": 456,
  "snippet": "profileDiv.innerHTML = getUserInput();"
}
```

**Investigation process:**
1. Read the chunk containing this line
2. Trace the data flow (see Data Flow Analysis below)
3. Check if input is sanitized before reaching the sink

### Step 3: Review Flagged Chunks Only

**DON'T read all chunks sequentially** - use `chunks_with_findings` array:
```json
"chunks_with_findings": [1, 3, 7, 9]
```

This means ONLY chunks 1, 3, 7, and 9 contain detected security patterns. Read these first:
```bash
read_file audit_workspace/app/app_part_001.js
read_file audit_workspace/app/app_part_003.js
read_file audit_workspace/app/app_part_007.js
read_file audit_workspace/app/app_part_009.js
```

**Each chunk header will show findings detected in that section.**

## Validation Rules - Critical Thinking Required

**The automated scan is a STARTING POINT, not final truth.** You must validate each finding:

### 1. Hardcoded Secrets (Pattern: `secrets`)

**Automated Detection:**
- Looks for: `apiKey = "..."`, `token = "..."`, `password = "..."`, JWT patterns, AWS keys, Stripe keys

**Manual Validation Required:**
```javascript
// FALSE POSITIVE - example/placeholder
const API_KEY = "your-api-key-here";  //  Not a real secret

// FALSE POSITIVE - test data
const mockToken = "fake-token-for-testing";  //  Not production secret

// TRUE POSITIVE - real hardcoded secret
const stripeKey = "sk_live_51HxYz...";  //  CRITICAL - real Stripe live key

// NEEDS VERIFICATION - check if production
const apiKey = "abc123xyz";  //  Could be real - investigate context
```

**Validation Steps:**
1. Check if value looks like placeholder text ("xxx", "your-key-here", "test")
2. Check surrounding comments for "example", "mock", "test"
3. For API keys: verify format matches real provider patterns (e.g., Stripe: `sk_live_`, AWS: `AKIA`)
4. Look for environment checks - if wrapped in `if (process.env.NODE_ENV === 'development')`, lower severity

### 2. DOM-Based XSS (Pattern: `dom_xss`)

**Automated Detection:**
- Looks for: `.innerHTML =`, `.outerHTML =`, `document.write()`, `eval()`, `setTimeout(string)`

**Manual Validation - TRACE DATA FLOW:**
```javascript
// FALSE POSITIVE - static content
div.innerHTML = "Static text";  //  No user input

// FALSE POSITIVE - sanitized input
div.innerHTML = DOMPurify.sanitize(userInput);  //  Properly sanitized

// TRUE POSITIVE - unsanitized user input
div.innerHTML = location.hash;  //  CRITICAL XSS vulnerability

// NEEDS INVESTIGATION - trace getParam function
div.innerHTML = getParam('name');  //  Check if getParam sanitizes
```

**Validation Steps:**
1. **Identify the source** - where does the data come from?
   - User-controlled: `location.*`, `document.cookie`, `localStorage`, URL params
   - Server-controlled: API responses (usually safer, but verify)
   - Static: Hardcoded strings (safe)

2. **Trace the data flow** - does it pass through sanitization?
   - Look for: `DOMPurify.sanitize()`, `.textContent` (safe alternative), HTML escaping functions
   - Search for the function name if data comes from helper function

3. **Check the sink** - is the operation actually dangerous?
   - `.innerHTML` with user input = XSS
   - `.textContent` with user input = SAFE (no script execution)

**Example data flow investigation:**
```javascript
// Found in chunk 3:
profileDiv.innerHTML = renderUserBio(userData.bio);

// Must find renderUserBio - check _SECURITY_REPORT for function location
// If renderUserBio is in chunk 5, read that chunk:
// read_file audit_workspace/app/app_part_005.js

// In chunk 5:
function renderUserBio(bio) {
  return bio.replace(/</g, '<');  //  Escaping - this is SAFE
}
```

### 3. User Input Sources (Pattern: `user_input`)

**These are NOT vulnerabilities by themselves** - they mark potential taint sources.

**You must trace where this input flows:**
```javascript
// Flagged as user_input source:
const userId = new URLSearchParams(location.search).get('id');

// Now search for where userId is used:
// grep -r "userId" audit_workspace/app/

// If you find:
element.innerHTML = userId;  //  This IS a vulnerability
fetch('/api/users/' + userId);  //  Potential SQL injection (backend issue)
console.log(userId);  //  Not a vulnerability
```

**Validation approach:**
1. Note the variable name capturing user input
2. Search for that variable in nearby code or use grep
3. Only flag if it reaches a dangerous sink without sanitization

### 4. Open Redirects (Pattern: `redirects`)

**Automated Detection:**
- Looks for: `window.location =`, `location.href =`, `location.replace()`

**Manual Validation:**
```javascript
// FALSE POSITIVE - static redirect
window.location = "/dashboard";  //  Hardcoded safe URL

// FALSE POSITIVE - validated redirect
const allowedUrls = ['/home', '/profile'];
if (allowedUrls.includes(url)) {
  window.location = url;  //  Whitelist validation
}

// TRUE POSITIVE - unvalidated redirect
window.location = params.get('redirect');  //  Open redirect vulnerability

// NEEDS INVESTIGATION - check validateUrl function
window.location = validateUrl(nextUrl);  //  Trace validation logic
```

**Validation steps:**
1. Check if URL is hardcoded (safe)
2. Check if URL comes from user input (vulnerable)
3. Check for validation: domain whitelist, starts with `/`, URL parsing checks

### 5. Insecure Communication (Pattern: `network`)

**Automated Detection:**
- Looks for: `fetch('http://...)`, `ws://`, non-HTTPS API calls

**Manual Validation:**
```javascript
// FALSE POSITIVE - localhost development
fetch('http://localhost:3000/api');  //  Dev environment, acceptable

// FALSE POSITIVE - internal network
fetch('http://192.168.1.100/data');  //  Often internal IP, context-dependent

// TRUE POSITIVE - production HTTP API call
fetch('http://api.example.com/user');  //  Should use HTTPS

// TRUE POSITIVE - unencrypted WebSocket
const ws = new WebSocket('ws://chat.example.com');  //  Should use wss://
```

**Validation steps:**
1. Check for localhost/127.0.0.1 (dev environment - lower severity)
2. Check for RFC 1918 private IPs (192.168.x.x, 10.x.x.x - may be intentional)
3. Check for production domains - MUST use HTTPS/WSS

## Data Flow Analysis - Connecting the Pieces

**When you find a potential vulnerability, you must trace the data flow:**

### Example: Tracing innerHTML XSS

**Step 1: Found in chunk 3:**
```javascript
// Line 456
displayMessage(userMessage);
```

**Step 2: Find displayMessage function:**
- Check chunk header "CONTEXT" - if it says "displayMessage", it's in this chunk
- Otherwise, search other chunks using grep:
```bash
  grep -r "function displayMessage\|const displayMessage" audit_workspace/app/
```

**Step 3: Read the function definition:**
```bash
# Output shows: app_part_007.js:123:function displayMessage(msg) {
read_file audit_workspace/app/app_part_007.js
```

**Step 4: Analyze the function:**
```javascript
function displayMessage(msg) {
  const div = document.getElementById('msg');
  div.innerHTML = msg;  //  SINK - is msg sanitized?
}
```

**Step 5: Trace back to the source:**
- Go back to where `displayMessage(userMessage)` was called
- Find where `userMessage` comes from:
```javascript
  const userMessage = location.hash.substring(1);  //  USER INPUT SOURCE
  displayMessage(userMessage);  //  FLOWS TO DANGEROUS SINK
```

**Conclusion: Confirmed XSS vulnerability** - user input from `location.hash` flows unsanitized to `innerHTML`.

### Cross-Chunk Data Flow Tracing

**Use grep to find function calls across chunks:**
```bash
# Find where a function is defined
grep -n "function handleAuth\|const handleAuth" audit_workspace/app/*.js

# Find where a function is called
grep -n "handleAuth(" audit_workspace/app/*.js

# Find variable usage
grep -n "apiKey" audit_workspace/app/*.js
```

**Read only the relevant chunks based on grep results.**

## Efficient Analysis Strategy

### Priority 1: Critical Findings (10 minutes)

1. Read `_SECURITY_REPORT.json`
2. Review all items in `critical_findings` array
3. For each critical finding:
   - Read the specific chunk containing it
   - Validate using rules above
   - If TRUE POSITIVE: document immediately

### Priority 2: Hotspots (15 minutes)

1. Review `hotspots` array in security report
2. Focus on hotspots with concerning contexts (auth, payment, user data)
3. Read relevant chunks and trace data flow
4. Validate and document

### Priority 3: Flagged Chunks (20 minutes)

1. Read chunks listed in `chunks_with_findings`
2. Review the security annotations in chunk headers
3. Validate findings that weren't in critical list
4. Look for patterns the automated scan may have missed

### Priority 4: Manual Code Review (30+ minutes)

**Only do this if time permits:**
- Read remaining chunks for logic flaws
- Look for business logic vulnerabilities
- Check authentication/authorization issues
- Review crypto implementations

## Common False Positives to Ignore

**The automated scan will flag these - you should SKIP them:**

1. **Development/Test Code:**
```javascript
   if (process.env.NODE_ENV === 'development') {
     apiKey = 'test-key';  //  Skip - dev only
   }
```

2. **Example/Placeholder Values:**
```javascript
   const API_KEY = "YOUR_API_KEY_HERE";  //  Skip - placeholder
```

3. **Static HTML:**
```javascript
   div.innerHTML = "Hello World";  //  Skip - no user input
```

4. **Localhost URLs:**
```javascript
   fetch('http://localhost:3000/api');  //  Skip - local dev
```

5. **Sanitized Content:**
```javascript
   div.innerHTML = DOMPurify.sanitize(input);  //  Skip - properly sanitized
```

6. **Safe Alternatives:**
```javascript
   div.textContent = userInput;  //  Skip - textContent is safe
```

## Security Patterns to Hunt BEYOND Automation

**The script catches common patterns, but YOU must find:**

### 1. Logic Flaws
- Authentication bypasses (missing auth checks)
- Authorization issues (user A accessing user B's data)
- Race conditions in async code
- Integer overflow in calculations

### 2. Prototype Pollution
```javascript
// Script may miss these:
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];  //  No __proto__ check
  }
}
```

### 3. Regex DoS (ReDoS)
```javascript
// Script won't catch these:
const regex = /^(a+)+$/;  //  Catastrophic backtracking
userInput.match(regex);  // Can hang server
```

### 4. Timing Attacks
```javascript
// Script won't catch these:
if (userPassword === storedPassword) {  //  Use crypto.timingSafeEqual
  // ...
}
```

### 5. Insecure Randomness
```javascript
// Script won't catch these:
const token = Math.random().toString(36);  //  Not cryptographically secure
// Should use: crypto.getRandomValues()
```

## Grep Patterns for Manual Hunting

**After reviewing automated findings, run these searches:**
```bash
# Authentication/Authorization
grep -r "role\|admin\|permissions\|authenticate" audit_workspace/app/

# Crypto usage
grep -r "crypto\|encrypt\|decrypt\|hash" audit_workspace/app/

# File operations (if server-side JS)
grep -r "readFile\|writeFile\|fs\." audit_workspace/app/

# Database queries (SQL injection potential)
grep -r "query\|execute\|SELECT\|INSERT" audit_workspace/app/

# Rate limiting (or lack thereof)
grep -r "rateLimit\|throttle" audit_workspace/app/

# Session management
grep -r "session\|cookie\|jwt" audit_workspace/app/
```

## Reporting Format

### Use This Template:
Security Audit: [filename]
Audited: [date]
Total Findings: X critical, Y high, Z medium
Executive Summary
[2-3 sentences on overall security posture]

Critical Findings
1. [Finding Title]

Severity: Critical
Location: app_part_003.js lines 250-255 (CONTEXT: ApiClient.authenticate)
Finding Source: Automated scan + manual validation
Vulnerability Type: Hardcoded Secret
Code:

javascript  const API_KEY = "sk_live_abc123xyz...";

Proof of Impact: Attacker can extract this key from bundled JavaScript and make unlimited API calls to Stripe, potentially charging unauthorized transactions.
Validation: Confirmed real Stripe live key format. Not wrapped in environment checks. Found in production bundle.
Recommendation:

Immediately rotate this API key in Stripe dashboard
Move key to server-side environment variable
Implement server-side proxy for Stripe API calls
Add secrets scanning to CI/CD pipeline




High Findings
1. [Finding Title]

Severity: High
Location: app_part_007.js line 456 (CONTEXT: MessageHandler.displayMessage)
Finding Source: Automated scan (hotspot) + data flow validation
Vulnerability Type: DOM-Based XSS
Data Flow:

Source: location.hash.substring(1) (line 445)
No sanitization applied
Sink: div.innerHTML = userMessage (line 456)


Code:

javascript  // Line 445
  const userMessage = location.hash.substring(1);
  
  // Line 456
  function displayMessage(msg) {
    msgDiv.innerHTML = msg;  // Vulnerable
  }
```
- **Proof of Concept**: `https://example.com/app#<img src=x onerror=alert(document.cookie)>`
- **Recommendation**:
  1. Replace `innerHTML` with `textContent` for plain text
  2. If HTML rendering needed, use DOMPurify library
  3. Implement Content Security Policy (CSP) headers

---

## Medium Findings

[Follow same format]

---

## Informational / False Positives

### Excluded Findings:
1. **API Key in line 123** - Validated as test environment placeholder ("your-api-key-here")
2. **innerHTML in line 234** - Validated as static HTML with no user input
3. **HTTP URL in line 567** - Localhost development endpoint

---

## Statistics
- Total lines analyzed: ~X,XXX
- Automated findings: XX
- True positives: YY (ZZ%)
- False positives: AA (BB%)
- Additional manual findings: CC
```

## Best Practices Summary

1. **ALWAYS start with `_SECURITY_REPORT.json`** - don't waste time reading clean chunks
2. **Validate automated findings** - regex patterns have false positives
3. **Trace data flows** - connect sources to sinks across chunks
4. **Use grep strategically** - find function definitions and variable usage
5. **Read chunk headers** - security annotations guide your review
6. **Focus on `chunks_with_findings`** - ignore clean chunks initially
7. **Think like an attacker** - ask "can I control this input?" and "where does it go?"
8. **Document validation steps** - explain WHY something is/isn't vulnerable
9. **Prioritize by impact** - secrets and XSS before info disclosure
10. **Use context from `hotspots`** - function names help understand code purpose
11. **Use `_structure.json` for targeted searches** - NEVER read the entire file at once (it can be thousands of lines)

## Using _structure.json Efficiently

**CRITICAL: DO NOT read the entire `_structure.json` file** - it contains metadata for every function/class and can be 5000+ lines.

**Instead, use grep to query it:**
```bash
# Find a specific function's location
grep -A 2 '"name": "handleAuth"' audit_workspace/app/_structure.json

# Find all functions in a specific context (e.g., inside AuthHandler class)
grep -A 2 '"parent": "AuthHandler"' audit_workspace/app/_structure.json

# Find what's defined around a specific line number
grep -B 1 -A 2 '"line": 45' audit_workspace/app/_structure.json
```

**Structure map format (for reference):**
```json
{
  "type": "function",
  "name": "validateUser",
  "line": 450,
  "end_line": 475,
  "parent": "AuthHandler"
}
```

**Use it when:**
- Tracing a function call found in a chunk (find where it's defined)
- Understanding code organization (what functions exist in which contexts)
- Calculating which chunk contains a function (line ÷ 400 ≈ chunk number)

## CRITICAL: Common Pitfalls to Avoid
- Reading the entire `_structure.json` (use grep instead)
- Trusting automated findings without validation
- Reading all chunks sequentially (waste of time)
- Flagging every `innerHTML` without checking if input is sanitized
- Reporting localhost URLs as production vulnerabilities
- Missing cross-chunk data flows (use grep to connect pieces)
- Ignoring the CONTEXT field in chunk headers
- Not explaining validation reasoning in reports
- Reporting test/example secrets as critical findings

## Workflow Checklist

- [ ] Run audit_prep.py script on target file(s)
- [ ] Read `_SECURITY_REPORT.json` first
- [ ] Review all `critical_findings` entries
- [ ] Validate each critical finding (trace data flow)
- [ ] Review `hotspots` array for context-aware issues
- [ ] Read chunks from `chunks_with_findings` list only
- [ ] Run manual grep searches for logic flaws
- [ ] Trace cross-chunk data flows using grep
- [ ] Document findings with validation reasoning
- [ ] Provide actionable remediation steps
- [ ] Generate final report with statistics

---

**Remember: Static analysis finds POTENTIAL issues. Your job is to VALIDATE and CONNECT them into actionable findings.**