#!/bin/bash
#
# Demo script for installing wolfSSL component from components.espressif.com
#
#   https://components.espressif.com/components/wolfssl/wolfssl
#
#
# This project assumes the ESP-IDF envoironment is already installed. See:
#
# See https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/
#
# Espressif IDF is typically in:
#   %userprofile%\esp
#
# VisualGDB is typically in:
# . /mnt/c/SysGCC/esp32/esp-idf/v5.0/export.sh

MY_IDF_PORT=/dev/ttyS23


# check if IDF_PATH is set
if [ -z "$IDF_PATH" ]; then
    echo "Please follows the instruction of ESP-IDF installation and set IDF_PATH."
    exit 1
fi

# make sure it actually exists
if [ ! -d "$IDF_PATH" ]; then
    echo "ESP-IDF Development Framework doesn't exist.: $IDF_PATH"
    exit 1
fi

# is export.sh in the IDF path?
if [ ! -e "$IDF_PATH/export.sh" ]; then
    echo "ESP-IDF export.sh: $IDF_PATH/export.sh"
    exit 1
fi

# Delete files not in GitHub to refresh a prevously-built project
if [ -d "./build" ]; then
    echo "Initializing local project..."
    echo "Removing ./build/ directory..."
    rm -rI ./build/

    echo "Removing ./managed_components/ directory..."
    rm -rI ./managed_components/

    echo "Removing ./main/idf_component.yml"
    rm ./main/idf_component.yml

    echo "Removing /sdkconfig"
    rm ./sdkconfig

    echo "Removing ./dependencies.lock"
    rm ./dependencies.lock
fi

echo "Using MY_IDF_PORT = $MY_IDF_PORT"

echo "Installing wolfSSL..."
idf.py add-dependency "wolfssl/wolfssl^5.6.0-stable"

echo "Bulding project..."
idf.py build

echo "Flashing project binary to device at $MY_IDF_PORT..."
idf.py -b 115200 -p $MY_IDF_PORT flash

idf.py -b 115200 -p $MY_IDF_PORT monitor
