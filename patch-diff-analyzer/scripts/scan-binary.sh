#!/bin/bash
# Usage: ./scan-binary.sh <file.jar/war/dll>

FILE="$1"

# Detect file size (cross-platform: Linux + macOS)
SIZE_BYTES=$(stat -c%s "$FILE" 2>/dev/null || stat -f%z "$FILE")
SIZE_MB=$((SIZE_BYTES / 1024 / 1024))

echo "--- Binary Size ---"
echo "$SIZE_MB MB"
echo ""

if [[ "$FILE" == *".jar" ]] || [[ "$FILE" == *".war" ]]; then
    echo "--- Top Level Java Packages (Frequency Count) ---"
    unzip -l "$FILE" 2>/dev/null \
      | grep ".class$" \
      | awk '{print $4}' \
      | cut -d/ -f1-3 \
      | sed 's|/|.|g' \
      | grep -vE "^java\.|^javax\.|^sun\.|^org\.springframework|^org\.apache|^com\.google|^org\.hibernate|^io\.netty" \
      | sort | uniq -c | sort -nr | head -n 15

elif [[ "$FILE" == *".dll" ]] || [[ "$FILE" == *".exe" ]]; then
    echo "--- .NET Namespaces (via strings analysis) ---"
    strings "$FILE" | grep -E "^[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\." | head -n 20
fi

echo ""

if [ "$SIZE_MB" -lt 20 ]; then
    echo "RECOMMENDATION: This binary is small (<20MB)."
    echo "Decompile the entire JAR/WAR at once — filtering unnecessary."
else
    echo "RECOMMENDATION: Large binary detected."
    echo "Ignore libraries like org.*, com.google.*, etc."
    echo "Focus on unique packages above for selective decompilation."
fi
