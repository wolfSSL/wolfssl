#!/bin/bash
set -euo pipefail

LOG=/tmp/wolfcrypt-renode.log
TIMEOUT=300  # Maximum 5 minutes

echo "Running wolfCrypt test in Renode..."

# Try to find Renode binary in common installation locations
# When installed via .deb package, Renode is typically in /usr/bin/renode
RENODE_BIN="${RENODE_BIN:-$(command -v renode 2>/dev/null || true)}"
if [ -z "$RENODE_BIN" ]; then
    # Check common installation paths (order matters - check standard locations first)
    for path in /usr/bin/renode /usr/local/bin/renode /opt/renode/renode; do
        if [ -x "$path" ]; then
            RENODE_BIN="$path"
            break
        fi
    done
fi

if [ -z "$RENODE_BIN" ] || [ ! -x "$RENODE_BIN" ]; then
    echo "Renode binary not found in image."
    echo "Checked paths: /usr/bin/renode, /usr/local/bin/renode, /opt/renode/renode"
    echo "PATH: $PATH"
    which renode || echo "renode not in PATH"
    exit 2
fi

echo "Using Renode binary: $RENODE_BIN"

# Determine Renode root directory (where platforms/ directory is located)
if [ -d "/opt/renode/platforms" ]; then
    RENODE_ROOT="/opt/renode"
elif [ -d "/usr/lib/renode/platforms" ]; then
    RENODE_ROOT="/usr/lib/renode"
elif [ -d "/usr/share/renode/platforms" ]; then
    RENODE_ROOT="/usr/share/renode"
else
    # Try to find Renode root by checking where the binary is
    RENODE_DIR=$(dirname "$(readlink -f "${RENODE_BIN}" 2>/dev/null || echo "${RENODE_BIN}")")
    if [ -d "${RENODE_DIR}/../platforms" ]; then
        RENODE_ROOT=$(readlink -f "${RENODE_DIR}/.." 2>/dev/null || echo "${RENODE_DIR}/..")
    else
        echo "Warning: Could not determine Renode root directory"
        RENODE_ROOT=""
    fi
fi

# Set RENODE_ROOT environment variable (Renode uses this to find platform files)
if [ -n "$RENODE_ROOT" ]; then
    export RENODE_ROOT
    echo "Using Renode root: ${RENODE_ROOT}"
    # Also create .renode-root file in firmware directory as backup
    echo "${RENODE_ROOT}" > /opt/firmware/.renode-root
    chmod 644 /opt/firmware/.renode-root
else
    echo "ERROR: Could not determine Renode root directory"
    exit 1
fi

# Verify platform file exists
PLATFORM_FILE="${RENODE_ROOT}/platforms/cpus/stm32h753.repl"
if [ ! -f "${PLATFORM_FILE}" ]; then
    echo "ERROR: Platform file not found at ${PLATFORM_FILE}"
    echo "Searching for platform files..."
    find "${RENODE_ROOT}" -name "stm32h753.repl" 2>/dev/null | head -5 || true
    exit 1
fi

echo "Platform file found at: ${PLATFORM_FILE}"

# Change to firmware directory
cd /opt/firmware

# Create a modified Renode script with absolute path to platform file
# This avoids the .renode-root file lookup issue
cat > /opt/firmware/run-renode-absolute.resc <<EOF
# Renode test script for STM32H753 (with absolute platform path)
using sysbus

mach create "stm32h753"

# Use absolute path to platform file to avoid .renode-root lookup issues
machine LoadPlatformDescription @${PLATFORM_FILE}

sysbus LoadELF @/opt/firmware/wolfcrypt_test.elf

# Connect USART3 to the console for wolfCrypt output
showAnalyzer usart3

# Start emulation and run for a long time
# The entrypoint script will kill Renode when test completes
emulation RunFor "600s"
EOF

# Start Renode in background, output to log (unbuffered)
# Use the modified script with absolute path
echo "Starting Renode with command: ${RENODE_BIN} --disable-xwt --console -e \"i @/opt/firmware/run-renode-absolute.resc\""
stdbuf -oL -eL "${RENODE_BIN}" --disable-xwt --console -e "i @/opt/firmware/run-renode-absolute.resc" > "${LOG}" 2>&1 &
RENODE_PID=$!
echo "Renode PID: $RENODE_PID"

# Monitor the log for completion, errors, and flush output frequently
START_TIME=$(date +%s)
RESULT=""
LAST_LOG_SIZE=0

while true; do
    # Check if Renode is still running
    if ! kill -0 "$RENODE_PID" 2>/dev/null; then
        break
    fi
    
    # Flush new log content to stdout (unbuffered)
    if [ -f "${LOG}" ]; then
        CURRENT_LOG_SIZE=$(stat -f%z "${LOG}" 2>/dev/null || stat -c%s "${LOG}" 2>/dev/null || echo 0)
        if [ "$CURRENT_LOG_SIZE" -gt "$LAST_LOG_SIZE" ]; then
            # Output new lines
            tail -c +$((LAST_LOG_SIZE + 1)) "${LOG}" 2>/dev/null | head -c $((CURRENT_LOG_SIZE - LAST_LOG_SIZE))
            LAST_LOG_SIZE=$CURRENT_LOG_SIZE
        fi
    fi
    
    # Check for Renode errors (must check before completion to catch errors early)
    if grep -q "\[ERROR\]" "${LOG}" 2>/dev/null; then
        echo ""
        echo "ERROR: Renode reported an error!"
        RESULT="renode_error"
        break
    fi
    
    # Check for completion messages
    if grep -q "=== wolfCrypt test passed! ===" "${LOG}" 2>/dev/null; then
        RESULT="passed"
        break
    fi
    
    if grep -q "=== wolfCrypt test FAILED ===" "${LOG}" 2>/dev/null; then
        RESULT="failed"
        break
    fi
    
    # Check timeout
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        echo ""
        echo "Timeout after ${TIMEOUT} seconds"
        RESULT="timeout"
        break
    fi
    
    sleep 0.5
done

# Kill Renode if still running
if kill -0 "$RENODE_PID" 2>/dev/null; then
    kill "$RENODE_PID" 2>/dev/null || true
    wait "$RENODE_PID" 2>/dev/null || true
fi

# Show the log output
cat "${LOG}"

# Report result
case "$RESULT" in
    passed)
        echo ""
        echo "wolfCrypt tests completed successfully."
        exit 0
        ;;
    failed)
        echo ""
        echo "wolfCrypt tests FAILED."
        exit 1
        ;;
    renode_error)
        echo ""
        echo "Renode reported an error - test aborted."
        exit 1
        ;;
    timeout)
        echo ""
        echo "wolfCrypt tests timed out after ${TIMEOUT} seconds."
        exit 1
        ;;
    *)
        echo ""
        echo "wolfCrypt tests did not report a result."
        exit 1
        ;;
esac

