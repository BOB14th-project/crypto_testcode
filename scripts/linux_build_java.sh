#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/build/java"

mkdir -p "$OUTPUT_DIR"

mapfile -t JAVA_SOURCES < <(find "$ROOT_DIR/tests" -name "*.java")

if [ ${#JAVA_SOURCES[@]} -eq 0 ]; then
    echo "No Java sources found under tests/."
    exit 0
fi

echo "Compiling ${#JAVA_SOURCES[@]} Java sources..."
javac -d "$OUTPUT_DIR" "${JAVA_SOURCES[@]}"
echo "Java classes written to $OUTPUT_DIR"
