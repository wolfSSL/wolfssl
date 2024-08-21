#!/usr/bin/env bash
#
# testAll.sh [keyword suffix]
#
# Build and compile the wolfssl_test for all platforms.
#
# Supply optional keyword suffix value for log file names.
#
# See testMonitor.sh for USB port settings.
#
# Define ESPIDF_PUTTY_MONITOR to a non-blank value to call putty.
# instead of using `idf.py monitor`
#==============================================================================

# Run shell check to ensure this a good script.
shellcheck "$0"

if [[ "$PATH" == *"rtos-sdk"* ]]; then
    echo "Error. Detected rtos-sdk in path."
    echo "Need to start with clean path (no prior idf.py setup) "
    exit 1
fi

# Save the current PATH to a temporary variable
ORIGINAL_PATH="$PATH"
echo "ORIGINAL_PATH=$PATH"

export ESPIDF_PUTTY_MONITOR="TRUE"

THIS_SUFFIX="$1"


#******************************************************************************
# ESP8266 uses rtos-sdk/v3.4 toolchain. Test this first, as it is slowest.
WRK_IDF_PATH=/mnt/c/SysGCC/esp8266/rtos-sdk/v3.4
#******************************************************************************

# Clear ESP-IDF environment variables to ensure clean start for export.sh
unset ESP_IDF_VERSION
unset ESP_ROM_ELF_DIR
unset IDF_DEACTIVATE_FILE_PATH
unset IDF_PATH
unset IDF_PYTHON_ENV_PATH
unset IDF_TOOLS_EXPORT_CMD
unset IDF_TOOLS_INSTALL_CMD
unset OPENOCD_SCRIPTS

echo "Run ESP8266 export.sh from ${WRK_IDF_PATH}"

# shell check should not follow into the ESP-IDF export.sh
# shellcheck disable=SC1091
. "$WRK_IDF_PATH"/export.sh

# Tensilica
./testMonitor.sh wolfssl_test esp8266 "$THIS_SUFFIX" || exit 1 # 2715073


#******************************************************************************
# ESP32[-N] uses esp-idf/v5.2 toolchain
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2
#******************************************************************************
# Restore the original PATH
export PATH="$ORIGINAL_PATH"

# Clear ESP-IDF environment variables to ensure clean start
unset ESP_IDF_VERSION
unset ESP_ROM_ELF_DIR
unset IDF_DEACTIVATE_FILE_PATH
unset IDF_PATH
unset IDF_PYTHON_ENV_PATH
unset IDF_TOOLS_EXPORT_CMD
unset IDF_TOOLS_INSTALL_CMD
unset OPENOCD_SCRIPTS

echo "Run ESP32 export.sh from ${WRK_IDF_PATH}"

# shell check should not follow into the ESP-IDF export.sh
# shellcheck disable=SC1091
. "$WRK_IDF_PATH"/export.sh

# Comment numeric values are recently observed runtime durations.
# Different tests may be enabled for each device.
# This list is not indicative of relative performance.

# Limited hardware acceleration, test slowest first:
./testMonitor.sh wolfssl_test esp32h2 "$THIS_SUFFIX" || exit 1 # 1424084 esp32h2 COM31" ok
./testMonitor.sh wolfssl_test esp8684 "$THIS_SUFFIX" || exit 1 # 1065290 esp8684 COM49" ok

# RISC-V
./testMonitor.sh wolfssl_test esp32c2 "$THIS_SUFFIX" || exit 1 # 1133856 esp32c2 COM79" ok
./testMonitor.sh wolfssl_test esp32c3 "$THIS_SUFFIX" || exit 1 # 344677  esp32c3 COM35"   NT
./testMonitor.sh wolfssl_test esp32c6 "$THIS_SUFFIX" || exit 1 # 346393  esp32c6 COM36" ok

# Xtensa
./testMonitor.sh wolfssl_test esp32   "$THIS_SUFFIX" || exit 1 # 259093  esp32   COM9"    NT
./testMonitor.sh wolfssl_test esp32s2 "$THIS_SUFFIX" || exit 1 # 305004  esp32s2 COM30"   NT
./testMonitor.sh wolfssl_test esp32s3 "$THIS_SUFFIX" || exit 1 # 267518  esp32s3 COM24"   NT

# Restore the original PATH
export PATH="$ORIGINAL_PATH"

echo "Done!"
