#!/bin/bash
#
# TLS-Anvil RFC compliance test script for wolfSSL
# Usage: ./tls-anvil-test.sh <mode> [extra_configure_flags]
#   mode: 'server' or 'client'
#   extra_configure_flags: additional ./configure options (optional)
#
# This script:
# 1. Builds wolfSSL with appropriate TLS options
# 2. Runs TLS-Anvil Docker container against wolfSSL
# 3. Collects and reports results
#
# Must be run from the wolfSSL source root directory.

set -e

MODE="${1:-server}"
EXTRA_FLAGS="${2:-}"

# Unique name for port/container isolation (set externally or default)
TEST_NAME="${TLS_ANVIL_TEST_NAME:-default}"

RESULTS_DIR="tls-anvil-results"
TLS_ANVIL_IMAGE="ghcr.io/tls-attacker/tlsanvil:latest"
TIMEOUT_SECONDS=3600
STRENGTH="${TLS_ANVIL_STRENGTH:-1}"

# Derive a unique port from the test name to avoid conflicts on parallel runs.
# Produces a port in the range 11111-11999.
PORT_HASH=$(echo -n "$TEST_NAME" | cksum | awk '{print $1}')
WOLFSSL_PORT=$((11111 + (PORT_HASH % 889)))

# Unique container name per run
CONTAINER_NAME="tls-anvil-${TEST_NAME}-$$"

log_info()  { echo "[INFO]  $1"; }
log_warn()  { echo "[WARN]  $1"; }
log_error() { echo "[ERROR] $1"; }

cleanup() {
    log_info "Cleaning up..."
    if [[ -f "$RESULTS_DIR/server.pid" ]]; then
        local pid
        pid=$(cat "$RESULTS_DIR/server.pid")
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        rm -f "$RESULTS_DIR/server.pid"
    fi
    if command -v fuser &> /dev/null; then
        fuser -k "${WOLFSSL_PORT}/tcp" 2>/dev/null || true
    fi
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    sleep 1
}

ensure_port_available() {
    local port=$1
    local attempt=0

    if command -v fuser &> /dev/null; then
        fuser -k "${port}/tcp" 2>/dev/null || true
    elif command -v lsof &> /dev/null; then
        lsof -ti:"${port}" | xargs kill -9 2>/dev/null || true
    fi

    while [ $attempt -lt 10 ]; do
        if ! (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -q ":${port} "; then
            return 0
        fi
        log_warn "Port ${port} still in use, waiting..."
        sleep 1
        attempt=$((attempt + 1))
    done

    log_error "Port ${port} still in use after 10 attempts"
    return 1
}

trap cleanup EXIT

# Clear any state from a previous run
cleanup

if [[ "$MODE" != "server" && "$MODE" != "client" ]]; then
    log_error "Invalid mode: $MODE. Must be 'server' or 'client'"
    exit 1
fi

log_info "TLS-Anvil Test - Mode: $MODE, Test: $TEST_NAME (port: $WOLFSSL_PORT)"
log_info "Extra configure flags: $EXTRA_FLAGS"

mkdir -p "$RESULTS_DIR"

# ---------------------------------------------------------------------------
# Build wolfSSL
# ---------------------------------------------------------------------------
log_info "Building wolfSSL..."
./autogen.sh

CONFIGURE_OPTS="--enable-asn=all"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-ocspstapling"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-tlsx"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-dtls"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-opensslextra"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-opensslall"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-supportedcurves"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-session-ticket"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-sni"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-alpn"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-truncatedhmac"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-extended-master"
CONFIGURE_OPTS="$CONFIGURE_OPTS --enable-enc-then-mac"
CONFIGURE_OPTS="$CONFIGURE_OPTS CPPFLAGS=-DWOLFSSL_EXTRA_ALERTS"

if [[ -n "$EXTRA_FLAGS" ]]; then
    CONFIGURE_OPTS="$CONFIGURE_OPTS $EXTRA_FLAGS"
fi

log_info "Configure options: $CONFIGURE_OPTS"
# shellcheck disable=SC2086
./configure $CONFIGURE_OPTS

make clean
make -j"$(nproc)"

# ---------------------------------------------------------------------------
# Server mode: wolfSSL listens, TLS-Anvil probes as client
# ---------------------------------------------------------------------------
if [[ "$MODE" == "server" ]]; then
    log_info "Starting wolfSSL server on port $WOLFSSL_PORT..."
    ensure_port_available "$WOLFSSL_PORT"

    if [[ ! -f "certs/server-cert.pem" ]] || [[ ! -f "certs/server-key.pem" ]]; then
        log_error "Certificate files not found in certs/ directory"
        exit 1
    fi

    # Wrapper loop: restarts the server if it exits so TLS-Anvil can reconnect
    # between test cases without the whole run failing.
    cat > "$RESULTS_DIR/run-server.sh" << 'SERVERSCRIPT'
#!/bin/bash
CHILD_PID=
cleanup() {
    [[ -n "$CHILD_PID" ]] && kill "$CHILD_PID" 2>/dev/null; wait "$CHILD_PID" 2>/dev/null
    exit 0
}
trap cleanup SIGTERM SIGINT
while true; do
    ./examples/server/server -p "$1" -C 4 -r -i -d -x \
        -c certs/server-cert.pem -k certs/server-key.pem -v d 2>&1 &
    CHILD_PID=$!
    wait "$CHILD_PID"
    echo "Server exited, restarting in 1 second..."
    sleep 1
done
SERVERSCRIPT
    chmod +x "$RESULTS_DIR/run-server.sh"

    "$RESULTS_DIR/run-server.sh" "$WOLFSSL_PORT" > "$RESULTS_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$RESULTS_DIR/server.pid"
    sleep 1

    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        log_error "wolfSSL server failed to start"
        cat "$RESULTS_DIR/server.log" || true
        exit 1
    fi

    log_info "wolfSSL server started (PID: $SERVER_PID)"

    if command -v openssl &> /dev/null; then
        log_info "Quick connectivity check..."
        echo "Q" | timeout 5 openssl s_client \
            -connect "127.0.0.1:$WOLFSSL_PORT" -tls1_2 2>&1 | head -5 \
            || log_warn "Pre-check had issues (not fatal)"
    fi

    log_info "Running TLS-Anvil (client mode, timeout: ${TIMEOUT_SECONDS}s, strength: $STRENGTH)..."
    ANVIL_EXIT_CODE=0
    timeout "$TIMEOUT_SECONDS" docker run --rm \
        --name "$CONTAINER_NAME" \
        --network host \
        -v "$(pwd)/$RESULTS_DIR:/output" \
        "$TLS_ANVIL_IMAGE" \
        -outputFolder /output \
        -parallelHandshakes 4 \
        -strength "$STRENGTH" \
        -connectionTimeout 200 \
        server \
        -connect "127.0.0.1:$WOLFSSL_PORT" \
        || ANVIL_EXIT_CODE=$?

    log_info "Stopping wolfSSL server..."
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true

    if [[ "$ANVIL_EXIT_CODE" -ne 0 ]]; then
        log_warn "TLS-Anvil exited $ANVIL_EXIT_CODE - last 50 lines of server log:"
        tail -50 "$RESULTS_DIR/server.log" || true
    fi

# ---------------------------------------------------------------------------
# Client mode: TLS-Anvil listens, wolfSSL connects on each test case
# ---------------------------------------------------------------------------
else
    log_info "Running TLS-Anvil (server mode, wolfSSL as client, timeout: ${TIMEOUT_SECONDS}s)..."
    ensure_port_available "$WOLFSSL_PORT"

    WOLFSSL_DIR="$(pwd)"

    # TLS-Anvil calls this script once per test case to trigger a client connection.
    cat > "$RESULTS_DIR/trigger-client.sh" << EOF
#!/bin/bash
cd "$WOLFSSL_DIR"
exec ./examples/client/client -h "127.0.0.1" -p "$WOLFSSL_PORT" -d -g -v d
EOF
    chmod +x "$RESULTS_DIR/trigger-client.sh"

    ANVIL_EXIT_CODE=0
    timeout "$TIMEOUT_SECONDS" docker run --rm \
        --name "$CONTAINER_NAME" \
        --network host \
        -v "$(pwd)/$RESULTS_DIR:/output" \
        -v "$WOLFSSL_DIR:$WOLFSSL_DIR" \
        "$TLS_ANVIL_IMAGE" \
        -outputFolder /output \
        -parallelHandshakes 3 \
        -parallelTests 3 \
        -strength "$STRENGTH" \
        client \
        -port "$WOLFSSL_PORT" \
        -triggerScript "$WOLFSSL_DIR/$RESULTS_DIR/trigger-client.sh" \
        || ANVIL_EXIT_CODE=$?
fi

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
log_info "Checking results..."

if [[ -f "$RESULTS_DIR/report.json" ]]; then
    log_info "report.json found"
    if command -v jq &> /dev/null; then
        TOTAL=$(jq '.TotalTests              // "N/A"' "$RESULTS_DIR/report.json" 2>/dev/null || echo "N/A")
        PASS=$( jq '.StrictlySucceededTests  // "N/A"' "$RESULTS_DIR/report.json" 2>/dev/null || echo "N/A")
        CONCEPT=$(jq '.ConceptuallySucceededTests // "N/A"' "$RESULTS_DIR/report.json" 2>/dev/null || echo "N/A")
        PARTIAL=$(jq '.PartiallyFailedTests   // "N/A"' "$RESULTS_DIR/report.json" 2>/dev/null || echo "N/A")
        FAIL=$( jq '.FullyFailedTests        // "N/A"' "$RESULTS_DIR/report.json" 2>/dev/null || echo "N/A")
        DISABLED=$(jq '.DisabledTests         // "N/A"' "$RESULTS_DIR/report.json" 2>/dev/null || echo "N/A")
        log_info "  Total:              $TOTAL"
        log_info "  Strictly Passed:    $PASS"
        log_info "  Conceptually OK:    $CONCEPT"
        log_info "  Partially Failed:   $PARTIAL"
        log_info "  Fully Failed:       $FAIL"
        log_info "  Disabled:           $DISABLED"

        cat > "$RESULTS_DIR/summary.txt" << EOF
TLS-Anvil Test Summary
======================
Mode:    $MODE
Date:    $(date)
Config:  $CONFIGURE_OPTS

Results:
  Total:              $TOTAL
  Strictly Passed:    $PASS
  Conceptually OK:    $CONCEPT
  Partially Failed:   $PARTIAL
  Fully Failed:       $FAIL
  Disabled:           $DISABLED
EOF
    fi
else
    log_warn "No report.json found"
    ls -la "$RESULTS_DIR/" || true
fi

if [[ "$ANVIL_EXIT_CODE" -ne 0 ]]; then
    log_error "TLS-Anvil exited with code $ANVIL_EXIT_CODE"
    # Exit non-zero so the workflow step is marked failed
    exit "$ANVIL_EXIT_CODE"
fi

log_info "TLS-Anvil testing complete"
