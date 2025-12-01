#!/bin/bash
# Decompile Java JAR files using jadx
# Usage: ./decompile-jar.sh <jar-file> <output-dir>

set -e

JAR_FILE="$1"
OUTPUT_DIR="$2"

if [ -z "$JAR_FILE" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <jar-file> <output-dir>"
    exit 1
fi

if [ ! -f "$JAR_FILE" ]; then
    echo "Error: JAR file not found: $JAR_FILE"
    exit 1
fi

echo "===================================="
echo "JAR Decompilation Script"
echo "===================================="
echo "Input JAR: $JAR_FILE"
echo "Output Dir: $OUTPUT_DIR"
echo ""

# Check for available decompilers
DECOMPILER=""

if command -v jadx &> /dev/null; then
    DECOMPILER="jadx"
    echo "Using jadx decompiler"
elif command -v jd-cli &> /dev/null; then
    DECOMPILER="jd-cli"
    echo "Using jd-cli decompiler"
elif command -v cfr &> /dev/null; then
    DECOMPILER="cfr"
    echo "Using CFR decompiler"
else
    echo "Error: No Java decompiler found!"
    echo ""
    echo "Please install one of the following:"
    echo "  - jadx (recommended): brew install jadx"
    echo "  - jd-cli: brew install jd-cli"
    echo "  - cfr: Download from https://www.benf.org/other/cfr/"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "Decompiling..."
echo ""

# Decompile based on available tool
case $DECOMPILER in
    jadx)
        jadx -d "$OUTPUT_DIR" \
             --no-res \
             --no-imports \
             --comments-level 'none' \
             "$JAR_FILE"
        ;;
    jd-cli)
        jd-cli -od "$OUTPUT_DIR" "$JAR_FILE"
        ;;
    cfr)
        java -jar "$(which cfr)" "$JAR_FILE" \
             --outputdir "$OUTPUT_DIR" \
             --caseinsensitivefs true
        ;;
esac

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Decompilation successful!"
    echo "Output directory: $OUTPUT_DIR"

    # Show statistics
    FILE_COUNT=$(find "$OUTPUT_DIR" -name "*.java" | wc -l | tr -d ' ')
    echo "Java files extracted: $FILE_COUNT"

    # Show directory structure
    echo ""
    echo "Directory structure:"
    tree -L 3 -d "$OUTPUT_DIR" 2>/dev/null || find "$OUTPUT_DIR" -type d -maxdepth 3 | head -20
else
    echo ""
    echo "✗ Decompilation failed!"
    exit 1
fi
