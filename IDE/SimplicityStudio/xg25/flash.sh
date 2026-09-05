#!/usr/bin/env bash
# Flash the built image to an attached EFR32xG25 kit and report the device.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$HERE/build}"
SILABS_HOME="${SILABS_HOME:-$HOME/.silabs}"

COMMANDER="${COMMANDER:-$(python3 -c "import json;print(json.load(open('$SILABS_HOME/tools.json'))['commander'][0]['path'])")/commander}"

IMAGE="${IMAGE:-$(find "$BUILD_DIR" -name '*.hex' | head -1)}"
if [ -z "$IMAGE" ]; then
    echo "No .hex found under $BUILD_DIR - run build.sh first." >&2
    exit 1
fi

echo "== device =="
"$COMMANDER" device info

echo
echo "== flashing $IMAGE =="
"$COMMANDER" flash "$IMAGE"

echo
echo "== reset =="
"$COMMANDER" device reset
