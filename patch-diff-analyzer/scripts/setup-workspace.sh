#!/bin/bash
# Setup workspace for patch diff analysis
# Usage: ./setup-workspace.sh <workspace-dir>

set -e

WORKSPACE_DIR="${1:-patch-analysis-workspace}"

echo "===================================="
echo "Patch Analysis Workspace Setup"
echo "===================================="
echo "Creating workspace: $WORKSPACE_DIR"
echo ""

# Create workspace directory
mkdir -p "$WORKSPACE_DIR"
cd "$WORKSPACE_DIR"

# Initialize git repository
if [ ! -d ".git" ]; then
    echo "Initializing git repository..."
    git init
    git config user.name "Patch Analyzer"
    git config user.email "analyzer@local"
    echo "✓ Git repository initialized"
else
    echo "✓ Git repository already exists"
fi

# Create directory structure
mkdir -p decompiled
mkdir -p output

echo "✓ Workspace structure created"
echo ""
echo "Workspace ready at: $(pwd)"
echo ""
echo "Next steps:"
echo "  1. Decompile unpatched binary to ./decompiled/"
echo "  2. Run: git add -A && git commit -m 'Unpatched version' && git tag unpatched"
echo "  3. Clear ./decompiled/ directory"
echo "  4. Decompile patched binary to ./decompiled/"
echo "  5. Run: git add -A && git commit -m 'Patched version' && git tag patched"
echo "  6. Run analyze-diff.sh to generate comparison"
