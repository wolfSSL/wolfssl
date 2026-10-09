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
#   -s, --sample <name>    Sample/test app to build
#   -d, --subdir <dir>     App subdir under zephyr/ (samples or tests; default samples)
#   -m, --modules <list>   West modules to fetch besides wolfSSL (default: all)
#   -l, --list <file>      Build each "<board> <app> [overlay]" line of <file>
#                          in one workspace, instead of -t/-s/-d/--extra-conf
#   -v, --verbose          Verbose compile output (show full compiler commands)
#   -W, --werror           Build with -Werror (treat warnings as errors)
#   --commit <sha>         Checkout specific commit after fetching branch
#   -c, --cmake-args <str> Extra CMake args passed after -- to west build
#   --extra-conf <file>    Extra Kconfig overlay (its directory is mounted)
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
#   # Run all CI builds for Zephyr 4.3.0 in one container
#   ./zephyr-test.sh -z v4.3.0 -l builds.txt
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
SUBDIR="samples"
WEST_MODULES=""
INTERACTIVE=0
VERBOSE=0
WERROR=0
WOLFSSL_COMMIT=""
CMAKE_EXTRA=""
EXTRA_CONF=""
BUILD_LIST=""
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

    if [[ "$major" -ge 4 && "$minor" -ge 4 ]]; then
        # Zephyr 4.4+ needs SDK 1.x (v0.29.2 image)
        echo "${GHCR}:v0.29.2"
    elif [[ "$major" -ge 4 && "$minor" -ge 2 ]]; then
        # Zephyr 4.2+ needs SDK 0.17.x (v0.28.8 image)
        echo "${GHCR}:v0.28.8"
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
        -d|--subdir)  SUBDIR="$2"; shift 2 ;;
        -m|--modules) WEST_MODULES="$2"; shift 2 ;;
        -l|--list)    BUILD_LIST="$2"; shift 2 ;;
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
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# One "<board> <app> [overlay]" line per build; overlays are read from CONF_DIR
CONF_DIR="${SCRIPT_DIR}"
if [[ -n "$BUILD_LIST" ]]; then
    BUILDS=$(grep -Ev '^[[:space:]]*(#|$)' "$BUILD_LIST")
    CONF_DIR="$(cd "$(dirname "$BUILD_LIST")" && pwd)"
    RUN_SLUG="$(basename "$BUILD_LIST" .txt)"
else
    BUILDS="${BOARD_TARGET} ${SUBDIR}/${SAMPLE_NAME} ${EXTRA_CONF##*/}"
    if [[ -n "$EXTRA_CONF" ]]; then
        CONF_DIR="$(cd "$(dirname "$EXTRA_CONF")" && pwd)"
    fi
    RUN_SLUG="${BOARD_TARGET//\//-}-${SAMPLE_NAME}"
fi

# Unique container name from version, builds, and PID to avoid collisions
ZVER_SLUG="${ZEPHYR_VERSION#v}"
CONTAINER_NAME="wolfssl-zephyr-${ZVER_SLUG}-${RUN_SLUG}-$$"

LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "${LOG_DIR}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/${ZVER_SLUG}-${RUN_SLUG}_${TIMESTAMP}.log"
ARTIFACTS_DIR="${SCRIPT_DIR}/artifacts"
mkdir -p "${ARTIFACTS_DIR}"
chmod 0777 "${ARTIFACTS_DIR}"

echo "==> wolfSSL repo:   ${WOLFSSL_REPO}"
echo "==> wolfSSL branch: ${WOLFSSL_BRANCH}"
echo "==> Zephyr version: ${ZEPHYR_VERSION}"
echo "==> Builds:"
echo "${BUILDS}" | sed 's/^/      /'
echo "==> Docker image:   ${DOCKER_IMAGE}"
[[ -n "$WEST_MODULES" ]] && echo "==> Modules:        ${WEST_MODULES}"
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
SUBDIR="__SUBDIR__"
WEST_MODULES="__WEST_MODULES__"
BUILDS="__BUILDS__"
WOLFSSL_REPO="__WOLFSSL_REPO__"
WOLFSSL_BRANCH="__WOLFSSL_BRANCH__"
WOLFSSL_COMMIT="__WOLFSSL_COMMIT__"
INTERACTIVE="__INTERACTIVE__"
VERBOSE="__VERBOSE__"
WERROR="__WERROR__"
CMAKE_EXTRA="__CMAKE_EXTRA__"

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

# --- 3. Update modules (including wolfSSL) ---
echo "==> [container] Running west update..."
export GIT_TERMINAL_PROMPT=0
if [[ -n "$WEST_MODULES" ]]; then
    west update -n -o=--depth=1 wolfssl ${WEST_MODULES}
else
    west update -n -o=--depth=1
fi

# --- 3b. Checkout specific commit if requested ---
if [[ -n "$WOLFSSL_COMMIT" ]]; then
    echo "==> [container] Checking out commit ${WOLFSSL_COMMIT}..."
    cd modules/crypto/wolfssl
    git fetch --unshallow "${WOLFSSL_REPO}" "${WOLFSSL_BRANCH}"
    git checkout "${WOLFSSL_COMMIT}"
    cd "${WORKDIR}/zephyrproject"
fi

# --- 4. Export Zephyr ---
# The image already provides west and the Zephyr Python requirements.
echo "==> [container] Exporting Zephyr..."
west zephyr-export

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
SUCCESS_RE="Benchmark complete\|Test complete\|Client Return: 0"
SUCCESS_RE="${SUCCESS_RE}\|PROJECT EXECUTION SUCCESSFUL"
RUN_TIMEOUT=300  # 5 minutes

# Run an emulator build until it prints a success string or times out
run_app() {
    local board="$1" build_dir="$2"
    local run_log="${build_dir}/run_output.log"
    local elapsed=0 pid

    echo "==> [container] Running sample on ${board}..."
    # New process group, so the kill below also stops the app itself
    setsid west build -d "${build_dir}" -t run > "${run_log}" 2>&1 &
    pid=$!

    while kill -0 "${pid}" 2>/dev/null; do
        if grep -q "${SUCCESS_RE}" "${run_log}" 2>/dev/null; then
            echo "==> [container] App completed successfully!"
            break
        fi
        if [[ $elapsed -ge $RUN_TIMEOUT ]]; then
            echo "==> [container] TIMEOUT: app did not complete" \
                 "within ${RUN_TIMEOUT}s"
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    kill -- "-${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true

    cat "${run_log}"

    if ! grep -q "${SUCCESS_RE}" "${run_log}"; then
        echo "==> [container] App exited without a success string"
        return 1
    fi
}

# Called with || so set -e does not apply; check each step
build_app() {
    local board="$1" app="$2" conf="$3" name="$4"
    local build_dir="build/${name}"
    local args="${CMAKE_ARGS}"
    local f

    if [[ -n "$conf" ]]; then
        args="${args} -DOVERLAY_CONFIG=/conf/${conf}"
    fi

    echo "==> [container] Building ${app} for ${board}..."
    west build -p always -d "${build_dir}" -b "${board}" \
        "modules/crypto/wolfssl/zephyr/${app}" \
        ${args:+-- $args} || return 1

    echo ""
    echo "==> [container] Build succeeded!"

    # Stage Membrowse inputs if the host mounted a writable /artifacts
    if [[ -d /artifacts && -w /artifacts ]]; then
        mkdir -p "/artifacts/${name}" || return 1
        for f in zephyr.elf linker.cmd zephyr.map; do
            if [[ -f "${build_dir}/zephyr/${f}" ]]; then
                cp "${build_dir}/zephyr/${f}" "/artifacts/${name}/" || return 1
            fi
        done
    fi

    case "${board}" in
        native_sim*|qemu_*)
            run_app "${board}" "${build_dir}" || return 1
            ;;
        *)
            echo "==> [container] Board '${board}' is not an emulator" \
                 "target, skipping run."
            echo "    Build artifacts are in:" \
                 "${WORKDIR}/zephyrproject/${build_dir}/zephyr/"
            ;;
    esac
}

if [[ "$INTERACTIVE" == "1" ]]; then
    echo ""
    echo "=========================================="
    echo " Interactive mode - workspace is ready"
    echo " Workspace: ${WORKDIR}/zephyrproject"
    echo " wolfSSL:   modules/crypto/wolfssl"
    echo ""
    echo " Example build commands:"
    echo "   west build -p always -b ${BOARD_TARGET} modules/crypto/wolfssl/zephyr/${SUBDIR}/${SAMPLE_NAME}"
    echo "   west build -t run"
    echo ""
    echo " To run twister tests:"
    echo "   ./zephyr/scripts/twister -T modules/crypto/wolfssl/zephyr/${SUBDIR}/${SAMPLE_NAME} -vvv"
    echo "=========================================="
    echo ""
    exec /bin/bash
else
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

    # Keep going after a failed build and report all failures at the end
    mapfile -t BUILD_LINES <<< "${BUILDS}"
    FAILED=()
    for LINE in "${BUILD_LINES[@]}"; do
        read -r BOARD APP CONF <<< "${LINE}"
        NAME="${BOARD//\//-}-${APP##*/}${CONF:+-${CONF%.conf}}"
        echo "::group::${NAME}"
        RC=0
        build_app "${BOARD}" "${APP}" "${CONF}" "${NAME}" || RC=$?
        echo "::endgroup::"
        if [[ $RC -ne 0 ]]; then
            echo "::error::Zephyr ${ZEPHYR_VERSION} ${NAME} failed"
            FAILED+=("${NAME}")
        fi
    done

    if [[ ${#FAILED[@]} -ne 0 ]]; then
        echo "==> [container] ${#FAILED[@]} of ${#BUILD_LINES[@]} failed:"
        printf '    %s\n' "${FAILED[@]}"
        exit 1
    fi
    echo "==> [container] All ${#BUILD_LINES[@]} builds passed"
fi
INNER_SCRIPT
)

# Substitute variables into the inner script
BUILD_SCRIPT="${BUILD_SCRIPT//__ZEPHYR_VERSION__/$ZEPHYR_VERSION}"
BUILD_SCRIPT="${BUILD_SCRIPT//__BOARD_TARGET__/$BOARD_TARGET}"
BUILD_SCRIPT="${BUILD_SCRIPT//__SAMPLE_NAME__/$SAMPLE_NAME}"
BUILD_SCRIPT="${BUILD_SCRIPT//__SUBDIR__/$SUBDIR}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WEST_MODULES__/$WEST_MODULES}"
BUILD_SCRIPT="${BUILD_SCRIPT//__BUILDS__/$BUILDS}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WOLFSSL_REPO__/$WOLFSSL_REPO}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WOLFSSL_BRANCH__/$WOLFSSL_BRANCH}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WOLFSSL_COMMIT__/$WOLFSSL_COMMIT}"
BUILD_SCRIPT="${BUILD_SCRIPT//__INTERACTIVE__/$INTERACTIVE}"
BUILD_SCRIPT="${BUILD_SCRIPT//__VERBOSE__/$VERBOSE}"
BUILD_SCRIPT="${BUILD_SCRIPT//__WERROR__/$WERROR}"
BUILD_SCRIPT="${BUILD_SCRIPT//__CMAKE_EXTRA__/$CMAKE_EXTRA}"

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
    -v "${ARTIFACTS_DIR}:/artifacts"
    -v "${CONF_DIR}:/conf:ro"
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
        echo "Docker:     ${DOCKER_IMAGE}"
        echo "Builds:"
        echo "${BUILDS}"
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
