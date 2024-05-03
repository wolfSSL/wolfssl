#!/bin/bash
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

# Save the current PATH to a temporary variable
ORIGINAL_PATH="$PATH"

export ESPIDF_PUTTY_MONITOR="TRUE"

THIS_SUFFIX="$1"

# Clear IDF path to ensure it is set by export.sh
IDF_PATH=

# set the path for this workspace IDF path (where export.sh is located)
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2
echo "Run ESP32 export.sh from ${WRK_IDF_PATH}"

# shell check should not follow into the ESP-IDF export.sh
# shellcheck disable=SC1091
. "${WRK_IDF_PATH}"/export.sh

echo "IDF_PATH = $IDF_PATH"

./testMonitor.sh wolfssl_test esp32   "$THIS_SUFFIX" || exit 1
./testMonitor.sh wolfssl_test esp32c2 "$THIS_SUFFIX" || exit 1
./testMonitor.sh wolfssl_test esp32c3 "$THIS_SUFFIX" || exit 1
./testMonitor.sh wolfssl_test esp32c6 "$THIS_SUFFIX" || exit 1
./testMonitor.sh wolfssl_test esp32s2 "$THIS_SUFFIX" || exit 1
./testMonitor.sh wolfssl_test esp32s3 "$THIS_SUFFIX" || exit 1
./testMonitor.sh wolfssl_test esp32h2 "$THIS_SUFFIX" || exit 1
./testMonitor.sh wolfssl_test esp8684 "$THIS_SUFFIX" || exit 1

# ESP8266 uses a different toolchain

# Restore the original PATH
export PATH=$ORIGINAL_PATH

IDF_PATH=
WRK_IDF_PATH=/mnt/c/SysGCC/esp8266/rtos-sdk/v3.4
echo "Run ESP8266 export.sh from ${WRK_IDF_PATH}"

# shell check should not follow into the ESP-IDF export.sh
# shellcheck disable=SC1091
. "$WRK_IDF_PATH"/export.sh

echo "IDF_PATH = $IDF_PATH"

./testMonitor.sh wolfssl_test esp8266 PR || exit 1

# Restore the original PATH
export PATH=$ORIGINAL_PATH

echo "Done!"
