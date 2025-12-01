#!/bin/bash
# Decompile .NET DLL/EXE files using ILSpy
# Usage: ./decompile-dll.sh <dll-file> <output-dir>

set -e

DLL_FILE="$1"
OUTPUT_DIR="$2"

if [ -z "$DLL_FILE" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <dll-file> <output-dir>"
    exit 1
fi

if [ ! -f "$DLL_FILE" ]; then
    echo "Error: DLL/EXE file not found: $DLL_FILE"
    exit 1
fi

echo "===================================="
echo ".NET Decompilation Script"
echo "===================================="
echo "Input File: $DLL_FILE"
echo "Output Dir: $OUTPUT_DIR"
echo ""

# Check for available decompilers
DECOMPILER=""

if command -v ilspycmd &> /dev/null; then
    DECOMPILER="ilspycmd"
    echo "Using ILSpy CLI decompiler"
elif command -v dotnet &> /dev/null && dotnet tool list -g | grep -q ilspycmd; then
    DECOMPILER="ilspycmd"
    echo "Using ILSpy CLI decompiler (dotnet tool)"
elif command -v monodis &> /dev/null; then
    DECOMPILER="monodis"
    echo "Using monodis (IL disassembler - warning: outputs IL, not C#)"
else
    echo "Error: No .NET decompiler found!"
    echo ""
    echo "Please install ILSpy CLI:"
    echo "  dotnet tool install -g ilspycmd"
    echo ""
    echo "Or install Mono tools:"
    echo "  brew install mono"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "Decompiling..."
echo ""

# Decompile based on available tool
case $DECOMPILER in
    ilspycmd)
        ilspycmd -o "$OUTPUT_DIR" -p "$DLL_FILE"
        ;;
    monodis)
        # monodis outputs IL code, not C#, but better than nothing
        echo "Warning: monodis outputs IL code, not C# source"
        BASENAME=$(basename "$DLL_FILE" .dll)
        BASENAME=$(basename "$BASENAME" .exe)
        monodis --output="$OUTPUT_DIR/${BASENAME}.il" "$DLL_FILE"
        ;;
esac

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Decompilation successful!"
    echo "Output directory: $OUTPUT_DIR"

    # Show statistics
    CS_FILE_COUNT=$(find "$OUTPUT_DIR" -name "*.cs" | wc -l | tr -d ' ')
    IL_FILE_COUNT=$(find "$OUTPUT_DIR" -name "*.il" | wc -l | tr -d ' ')

    if [ "$CS_FILE_COUNT" -gt 0 ]; then
        echo "C# files extracted: $CS_FILE_COUNT"
    fi

    if [ "$IL_FILE_COUNT" -gt 0 ]; then
        echo "IL files extracted: $IL_FILE_COUNT"
    fi

    # Show directory structure
    echo ""
    echo "Directory structure:"
    tree -L 3 -d "$OUTPUT_DIR" 2>/dev/null || find "$OUTPUT_DIR" -type d -maxdepth 3 | head -20
else
    echo ""
    echo "✗ Decompilation failed!"
    exit 1
fi
