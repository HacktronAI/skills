#!/bin/bash
set -e

JAR_FILE="$1"
OUTPUT_DIR="$2"
FILTER_PACKAGE="$3"

if [ -z "$JAR_FILE" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <jar-file> <output-dir> [package]"
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
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

if [ -n "$FILTER_PACKAGE" ]; then
    TEMP_DIR="temp_extraction"
    rm -rf "$TEMP_DIR"
    mkdir -p "$TEMP_DIR"

    FILTER_PATH=$(echo "$FILTER_PACKAGE" | sed 's/\./\//g')

    unzip -q "$JAR_FILE" "BOOT-INF/classes/$FILTER_PATH/*" -d "$TEMP_DIR" 2>/dev/null || true
    unzip -q "$JAR_FILE" "WEB-INF/classes/$FILTER_PATH/*" -d "$TEMP_DIR" 2>/dev/null || true
    unzip -q "$JAR_FILE" "$FILTER_PATH/*" -d "$TEMP_DIR" 2>/dev/null || true

    if [ -z "$(find "$TEMP_DIR" -name '*.class' 2>/dev/null)" ]; then
        echo "No classes found for package: $FILTER_PACKAGE"
        exit 1
    fi

    case $DECOMPILER in
        jadx)
            jadx -d "$OUTPUT_DIR" --no-res --no-imports "$TEMP_DIR"
            ;;
        jd-cli)
            jd-cli -od "$OUTPUT_DIR" "$TEMP_DIR"
            ;;
        cfr)
            find "$TEMP_DIR" -name "*.class" -exec java -jar "$(which cfr)" {} --outputdir "$OUTPUT_DIR" \;
            ;;
    esac

else
    case $DECOMPILER in
        jadx)
            jadx -d "$OUTPUT_DIR" --no-res --no-imports "$JAR_FILE"
            ;;
        jd-cli)
            jd-cli -od "$OUTPUT_DIR" "$JAR_FILE"
            ;;
        cfr)
            java -jar "$(which cfr)" "$JAR_FILE" --outputdir "$OUTPUT_DIR"
            ;;
    esac
fi

echo ""
echo "✓ Decompilation successful!"
echo "Output directory: $OUTPUT_DIR"

FILE_COUNT=$(find "$OUTPUT_DIR" -name "*.java" | wc -l | tr -d ' ')
echo "Java files extracted: $FILE_COUNT"

echo ""
echo "Directory structure:"
tree -L 3 -d "$OUTPUT_DIR" 2>/dev/null || find "$OUTPUT_DIR" -type d -maxdepth 3 | head -20
