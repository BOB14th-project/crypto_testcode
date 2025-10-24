#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CMAKE_BUILD_DIR="$ROOT_DIR/build/cmake"

BUILD_CONFIG="Release"
if [[ $# -ge 1 ]]; then
  BUILD_CONFIG="$1"
fi

echo "[CMake] Generating build files (config: $BUILD_CONFIG)"
cmake -S "$ROOT_DIR" -B "$CMAKE_BUILD_DIR" -DCMAKE_BUILD_TYPE=$BUILD_CONFIG

echo "[CMake] Building targets"
cmake --build "$CMAKE_BUILD_DIR" --config "$BUILD_CONFIG"

echo "[Java] Compiling sources"
"$ROOT_DIR/scripts/linux_build_java.sh"

printf "\nBuild completed (config: %s). Binaries under %s/bin\n" "$BUILD_CONFIG" "$ROOT_DIR/build"
