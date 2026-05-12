#!/bin/bash
#
# zephyr-test.sh - Build and test wolfSSL Zephyr samples in a Docker container
#
# Usage:
#   ./zephyr-test.sh [options]
#
# Options:
#   -r, --repo <url>       wolfSSL git repo URL
#   -b, --branch <branch>  wolfSSL branch/revision
#   -z, --zephyr <version> Zephyr version tag
#   -t, --target <board>   Board target
#   -s, --sample <name>    Sample to build
#   -v, --verbose          Verbose compile output (show full compiler commands)
#   -W, --werror           Build with -Werror (treat warnings as errors)
#   --commit <sha>         Checkout specific commit after fetching branch
#   -c, --cmake-args <str> Extra CMake args passed after -- to west build
#   --extra-conf <file>    Extra Kconfig overlay (copied into container)
#   -i, --interactive      Drop into interactive shell
#   -h, --help             Show this help
#
# Examples:
#   # Test master against Zephyr 4.1.0 for native_sim
#   ./zephyr-test.sh
#
#   # Test a specific branch for frdm_rw612 on Zephyr 4.3.0
#   ./zephyr-test.sh -b zephyr-4_3_0-posix-fix -z v4.3.0 -t frdm_rw612/rw612
#
#   # Test with Zephyr 4.3.0 on native_sim
#   ./zephyr-test.sh -z v4.3.0
#
#   # Interactive shell to debug
#   ./zephyr-test.sh -z v4.3.0 -i
#
#   # Test a fork
#   ./zephyr-test.sh -r https://github.com/myuser/wolfssl -b my-fix -z v4.3.0
#
#   # Build with -Werror like customer
#   ./zephyr-test.sh -z v4.3.0 -W
#
#   # Pass extra cmake args
#   ./zephyr-test.sh -z v4.3.0 -c "-DCMAKE_C_FLAGS=-U_POSIX_C_SOURCE"

set -euo pipefail

# Defaults
WOLFSSL_REPO="https://github.com/wolfSSL/wolfssl"
WOLFSSL_BRANCH="master"
ZEPHYR_VERSION="v4.1.0"
BOARD_TARGET="native_sim"
SAMPLE_NAME="wolfssl_tls_sock"
INTERACTIVE=0
VERBOSE=0
WERROR=0
WOLFSSL_COMMIT=""
CMAKE_EXTRA=""
EXTRA_CONF=""
CONTAINER_NAME=""  # set dynamically after arg parsing

GHCR="ghcr.io/zephyrproject-rtos/zephyr-build"

usage() {
    sed -n '3,/^$/s/^# \?//p' "$0"
    exit 0
}

select_docker_image() {
    local ver="${1#v}"
    local major="${ver%%.*}"
    local minor="${ver#*.}"
    minor="${minor%%.*}"

    if [[ "$major" -ge 4 && "$minor" -ge 2 ]]; then
        # Zephyr 4.2+ needs SDK 0.17.x (v0.28.7 image)
        echo "${GHCR}:v0.28.7"
    elif [[ "$major" -ge 4 ]]; then
        # Zephyr 4.0-4.1 needs SDK 0.17.0 (v0.27.4 image; v0.26.18/v0.28.7 picolibc is incompatible)
        echo "${GHCR}:v0.27.4"
    else
        # Zephyr 3.x and older
        echo "${GHCR}:v0.26.18"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--repo)    WOLFSSL_REPO="$2"; shift 2 ;;
        -b|--branch)  WOLFSSL_BRANCH="$2"; shift 2 ;;
        -z|--zephyr)  ZEPHYR_VERSION="$2"; shift 2 ;;
        -t|--target)  BOARD_TARGET="$2"; shift 2 ;;
        -s|--sample)  SAMPLE_NAME="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -W|--werror) WERROR=1; shift ;;
        --commit) WOLFSSL_COMMIT="$2"; shift 2 ;;
        -c|--cmake-args) CMAKE_EXTRA="$2"; shift 2 ;;
        --extra-conf) EXTRA_CONF="$2"; shift 2 ;;
        -i|--interactive) INTERACTIVE=1; shift ;;
        -h|--help)    usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

DOCKER_IMAGE=$(select_docker_image "$ZEPHYR_VERSION")

# Build a unique container name from version, board, sample, and PID to avoid collisions
ZVER_SLUG="${ZEPHYR_VERSION#v}"
BOARD_SLUG="${BOARD_TARGET//\//-}"
CONTAINER_NAME="wolfssl-zephyr-${ZVER_SLUG}-${BOARD_SLUG}-${SAMPLE_NAME}-$$"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "${LOG_DIR}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/${BOARD_SLUG}_${TIMESTAMP}.log"

echo "==> wolfSSL repo:   ${WOLFSSL_REPO}"
echo "==> wolfSSL branch: ${WOLFSSL_BRANCH}"
echo "==> Zephyr version: ${ZEPHYR_VERSION}"
echo "==> Board target:   ${BOARD_TARGET}"
echo "==> Sample:         ${SAMPLE_NAME}"
echo "==> Docker image:   ${DOCKER_IMAGE}"
[[ -n "$WOLFSSL_COMMIT" ]] && echo "==> Commit:         ${WOLFSSL_COMMIT}"
[[ "$WERROR" == "1" ]] && echo "==> Werror:         enabled"
[[ -n "$CMAKE_EXTRA" ]] && echo "==> CMake args:     ${CMAKE_EXTRA}"
[[ -n "$EXTRA_CONF" ]] && echo "==> Extra conf:     ${EXTRA_CONF}"
echo "==> Log file:       ${LOG_FILE}"
echo ""

# Pull the Docker image
echo "==> Pulling Docker image..."
docker pull "${DOCKER_IMAGE}"

# Build the script that runs inside the container
BUILD_SCRIPT=$(cat <<'INNER_SCRIPT'
#!/bin/bash
set -euo pipefail

ZEPHYR_VERSION="__ZEPHYR_VERSION__"
BOARD_TARGET="__BOARD_TARGET__"
SAMPLE_NAME="__SAMPLE_NAME__"
WOLFSSL_REPO="__WOLFSSL_REPO__"
WOLFSSL_BRANCH="__WOLFSSL_BRANCH__"
WOLFSSL_COMMIT="__WOLFSSL_COMMIT__"
INTERACTIVE="__INTERACTIVE__"
VERBOSE="__VERBOSE__"
WERROR="__WERROR__"
CMAKE_EXTRA="__CMAKE_EXTRA__"
EXTRA_CONF="__EXTRA_CONF__"
EXTRA_CONF_CONTENT="__EXTRA_CONF_CONTENT__"

WORKDIR="/workdir"
cd "$WORKDIR"

# --- 1. Initialize Zephyr workspace ---
echo "==> [container] Initializing Zephyr workspace (${ZEPHYR_VERSION})..."
west init --mr "${ZEPHYR_VERSION}" zephyrproject
cd zephyrproject

# --- 2. Add wolfSSL to the west manifest ---
echo "==> [container] Adding wolfSSL to west.yml (${WOLFSSL_REPO}@${WOLFSSL_BRANCH})..."
cd zephyr

# Use sed to inject wolfSSL remote and project into west.yml,
# same approach as the wolfSSL CI workflow
REPO_BASE=$(echo "${WOLFSSL_REPO}" | sed 's|/[^/]*$||')
REF=$(echo "${WOLFSSL_BRANCH}" | sed 's/\//\\\//g')

sed -i "s|remotes:|remotes:\n    - name: wolfssl\n      url-base: ${REPO_BASE}|" west.yml
sed -i "s|projects:|projects:\n    - name: wolfssl\n      path: modules/crypto/wolfssl\n      remote: wolfssl\n      revision: ${REF}|" west.yml

echo "==> [container] Updated west.yml:"
grep -A2 "wolfssl" west.yml
cd ..

# --- 3. Update all modules (including wolfSSL) ---
echo "==> [container] Running west update..."
export GIT_TERMINAL_PROMPT=0
west update -n -o=--depth=1

# --- 3b. Checkout specific commit if requested ---
if [[ -n "$WOLFSSL_COMMIT" ]]; then
    echo "==> [container] Checking out commit ${WOLFSSL_COMMIT}..."
    cd modules/crypto/wolfssl
    git fetch --unshallow "${WOLFSSL_REPO}" "${WOLFSSL_BRANCH}"
    git checkout "${WOLFSSL_COMMIT}"
    cd "${WORKDIR}/zephyrproject"
fi

# --- 4. Export and install deps ---
echo "==> [container] Exporting Zephyr..."
west zephyr-export

echo "==> [container] Installing host packages (newlib, python3-venv)..."
sudo apt-get update -qq && sudo apt-get install -y -qq python3-venv libnewlib-dev >/dev/null 2>&1 || true
python3 -m venv .venv
source .venv/bin/activate
pip3 install west
echo "==> [container] Installing Python dependencies..."
pip3 install -r zephyr/scripts/requirements.txt

export ZEPHYR_BASE="${WORKDIR}/zephyrproject/zephyr"

# Ensure Zephyr SDK is found (enables newlib for native_sim)
if [[ -z "${ZEPHYR_SDK_INSTALL_DIR:-}" ]]; then
    SDK_DIR=$(find /opt -maxdepth 2 -name "zephyr-sdk-*" -type d 2>/dev/null | head -1)
    if [[ -n "$SDK_DIR" ]]; then
        export ZEPHYR_SDK_INSTALL_DIR="$SDK_DIR"
        echo "==> [container] Found SDK: ${ZEPHYR_SDK_INSTALL_DIR}"
    fi
fi

# --- 5. Build or interactive ---
if [[ "$INTERACTIVE" == "1" ]]; then
    echo ""
    echo "=========================================="
    echo " Interactive mode - workspace is ready"
    echo " Workspace: ${WORKDIR}/zephyrproject"
    echo " wolfSSL:   modules/crypto/wolfssl"
    echo ""
    echo " Example build commands:"
    echo "   west build -p always -b ${BOARD_TARGET} modules/crypto/wolfssl/zephyr/samples/${SAMPLE_NAME}"
    echo "   west build -t run"
    echo ""
    echo " To run twister tests:"
    echo "   ./zephyr/scripts/twister -T modules/crypto/wolfssl/zephyr/samples/${SAMPLE_NAME} -vvv"
    echo "=========================================="
    echo ""
    exec /bin/bash
else
    if [[ -n "$EXTRA_CONF" ]]; then
        echo "$EXTRA_CONF_CONTENT" > /workdir/zephyrproject/extra.conf
        echo "==> [container] Extra conf written to /workdir/zephyrproject/extra.conf"
        cat /workdir/zephyrproject/extra.conf
    fi

    echo "==> [container] Building sample: ${SAMPLE_NAME} for ${BOARD_TARGET}..."
    CMAKE_ARGS=""
    if [[ "$VERBOSE" == "1" ]]; then
        CMAKE_ARGS="${CMAKE_ARGS} -DCMAKE_VERBOSE_MAKEFILE=ON"
    fi
    if [[ "$WERROR" == "1" ]]; then
        CMAKE_ARGS="${CMAKE_ARGS} -DCMAKE_C_FLAGS=-Werror"
    fi
    if [[ -n "$CMAKE_EXTRA" ]]; then
        CMAKE_ARGS="${CMAKE_ARGS} ${CMAKE_EXTRA}"
    fi

    if [[ -n "$EXTRA_CONF" ]]; then
        CMAKE_ARGS="${CMAKE_ARGS} -DOVERLAY_CONFIG=/workdir/zephyrproject/extra.conf"
    fi

    west build -p always -b "${BOARD_TARGET}" \
        "modules/crypto/wolfssl/zephyr/samples/${SAMPLE_NAME}" \
        ${CMAKE_ARGS:+-- $CMAKE_ARGS}

    echo ""
    echo "==> [container] Build succeeded!"

    # Run the app for emulator targets and watch for completion
    case "${BOARD_TARGET}" in
        native_sim*|qemu_*)
            echo "==> [container] Running sample on ${BOARD_TARGET}..."
            RUN_TIMEOUT=300  # 5 minutes
            RUN_LOG="/tmp/run_output.log"
            APP_RC=1

            west build -t run > "${RUN_LOG}" 2>&1 &
            RUN_PID=$!

            ELAPSED=0
            while kill -0 "${RUN_PID}" 2>/dev/null; do
                if [[ $ELAPSED -ge $RUN_TIMEOUT ]]; then
                    echo "==> [container] TIMEOUT: app did not complete within ${RUN_TIMEOUT}s"
                    kill "${RUN_PID}" 2>/dev/null || true
                    wait "${RUN_PID}" 2>/dev/null || true
                    cat "${RUN_LOG}"
                    exit 1
                fi
                # Check for success strings
                if grep -q "Benchmark complete\|Test complete\|Client Return: 0" "${RUN_LOG}" 2>/dev/null; then
                    echo "==> [container] App completed successfully!"
                    APP_RC=0
                    kill "${RUN_PID}" 2>/dev/null || true
                    wait "${RUN_PID}" 2>/dev/null || true
                    break
                fi
                sleep 2
                ELAPSED=$((ELAPSED + 2))
            done

            cat "${RUN_LOG}"

            if [[ $APP_RC -ne 0 ]]; then
                # Process exited on its own - check if it printed a success string
                if grep -q "Benchmark complete\|Test complete\|Client Return: 0" "${RUN_LOG}" 2>/dev/null; then
                    APP_RC=0
                else
                    echo "==> [container] App exited without a success string"
                    exit 1
                fi
            fi
            ;;
        *)
            echo "==> [container] Board '${BOARD_TARGET}' is not an emulator target, skipping run."
            echo "    Build artifacts are in: ${WORKDIR}/zephyrproject/build/zephyr/"
            ;;
    esac
fi
INNER_SCRIPT
)

# Substitute variables into the inner script
BUILD_SCRIPT="${BUILD_SCRIPT//__ZEPHYR_VERSION__/$ZEPHYR_VERSION}"
BUILD_SCRIPT="${BUILD_SCRIPT//__BOARD_TARGET__/$BOARD_TARGET}"
BUILD_SCRIPT="${BUILD_SCRIPT//__SAMPLE_NAME__/$SAMPLE_NAME}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WOLFSSL_REPO__/$WOLFSSL_REPO}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WOLFSSL_BRANCH__/$WOLFSSL_BRANCH}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WOLFSSL_COMMIT__/$WOLFSSL_COMMIT}"
BUILD_SCRIPT="${BUILD_SCRIPT//__INTERACTIVE__/$INTERACTIVE}"
BUILD_SCRIPT="${BUILD_SCRIPT//__VERBOSE__/$VERBOSE}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WERROR__/$WERROR}"
BUILD_SCRIPT="${BUILD_SCRIPT//__CMAKE_EXTRA__/$CMAKE_EXTRA}"
if [[ -n "$EXTRA_CONF" ]]; then
    EXTRA_CONF_CONTENT=$(cat "$EXTRA_CONF")
    BUILD_SCRIPT="${BUILD_SCRIPT//__EXTRA_CONF__/yes}"
    BUILD_SCRIPT="${BUILD_SCRIPT//__EXTRA_CONF_CONTENT__/$EXTRA_CONF_CONTENT}"
else
    BUILD_SCRIPT="${BUILD_SCRIPT//__EXTRA_CONF__/}"
    BUILD_SCRIPT="${BUILD_SCRIPT//__EXTRA_CONF_CONTENT__/}"
fi

# Clean up container on exit (covers crashes, interrupts, and normal exit)
cleanup() {
    docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

# Stop any existing container with the same name
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

# Build docker run args
DOCKER_ARGS=(
    --name "${CONTAINER_NAME}"
    --rm
)

if [[ "$INTERACTIVE" == "1" ]]; then
    DOCKER_ARGS+=(-it)
fi

echo "==> Starting container..."
echo ""

if [[ "$INTERACTIVE" == "1" ]]; then
    docker run "${DOCKER_ARGS[@]}" \
        "${DOCKER_IMAGE}" \
        bash -c "${BUILD_SCRIPT}"
else
    {
        echo "===== wolfSSL Zephyr Test Log ====="
        echo "Date:       $(date)"
        echo "Zephyr:     ${ZEPHYR_VERSION}"
        echo "Repo:       ${WOLFSSL_REPO}"
        echo "Branch:     ${WOLFSSL_BRANCH}"
        echo "Board:      ${BOARD_TARGET}"
        echo "Sample:     ${SAMPLE_NAME}"
        echo "Docker:     ${DOCKER_IMAGE}"
        echo "==================================="
        echo ""
    } > "${LOG_FILE}"

    set +e
    set -o pipefail
    docker run "${DOCKER_ARGS[@]}" \
        "${DOCKER_IMAGE}" \
        bash -c "${BUILD_SCRIPT}" 2>&1 \
        | tee -a "${LOG_FILE}"
    RC=$?
    set -e

    echo ""
    echo "${LOG_FILE}"
    exit $RC
fi
