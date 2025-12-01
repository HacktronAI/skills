#!/bin/bash
# Analyze differences between two decompiled versions using git
# Usage: ./analyze-diff.sh <workspace-dir>

set -e

WORKSPACE_DIR="${1:-.}"

if [ ! -d "$WORKSPACE_DIR" ]; then
    echo "Error: Workspace directory not found: $WORKSPACE_DIR"
    exit 1
fi

cd "$WORKSPACE_DIR"

if [ ! -d ".git" ]; then
    echo "Error: Not a git repository. Run setup-workspace.sh first."
    exit 1
fi

echo "===================================="
echo "Patch Diff Analysis"
echo "===================================="
echo "Workspace: $WORKSPACE_DIR"
echo ""

# Check for commits
COMMIT_COUNT=$(git rev-list --count HEAD 2>/dev/null || echo "0")

if [ "$COMMIT_COUNT" -lt 2 ]; then
    echo "Error: Need at least 2 commits (unpatched and patched versions)"
    echo "Current commit count: $COMMIT_COUNT"
    exit 1
fi

# Get commit information
echo "Commit History:"
git log --oneline --decorate -10
echo ""

# Determine commits to compare
if git rev-parse unpatched >/dev/null 2>&1 && git rev-parse patched >/dev/null 2>&1; then
    UNPATCHED_REF="unpatched"
    PATCHED_REF="patched"
    echo "Using tagged references: unpatched -> patched"
elif [ "$COMMIT_COUNT" -ge 2 ]; then
    UNPATCHED_REF="HEAD~1"
    PATCHED_REF="HEAD"
    echo "Using recent commits: HEAD~1 -> HEAD"
else
    echo "Error: Cannot determine commits to compare"
    exit 1
fi

echo ""
echo "===================================="
echo "Diff Statistics"
echo "===================================="

# Get statistics
git diff --stat "$UNPATCHED_REF" "$PATCHED_REF"

echo ""
echo "===================================="
echo "Changed Files"
echo "===================================="

# List changed files
git diff --name-status "$UNPATCHED_REF" "$PATCHED_REF"

echo ""
echo "===================================="
echo "Generating Detailed Diff"
echo "===================================="

# Generate detailed diff
DIFF_FILE="patch-analysis.diff"
git diff "$UNPATCHED_REF" "$PATCHED_REF" > "$DIFF_FILE"

if [ -s "$DIFF_FILE" ]; then
    DIFF_LINES=$(wc -l < "$DIFF_FILE" | tr -d ' ')
    echo "✓ Diff generated: $DIFF_FILE"
    echo "  Total lines: $DIFF_LINES"

    # Also create a more readable side-by-side summary
    git diff --name-only "$UNPATCHED_REF" "$PATCHED_REF" > changed-files.txt
    echo "✓ Changed files list: changed-files.txt"
else
    echo "✗ No differences found!"
    exit 1
fi

echo ""
echo "===================================="
echo "Analysis Complete"
echo "===================================="
echo ""
echo "Generated files:"
echo "  - $DIFF_FILE : Complete unified diff for analysis"
echo "  - changed-files.txt : List of changed files"
echo ""
echo "The diff is ready for LLM analysis to identify security-relevant changes."
