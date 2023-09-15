#!/bin/bash
#
# wolfssl_build_example.sh
#
# Script to build wolfSSL examples for publish to Espressif ESP Registry.
# This file is not needed by end users.
#

# the first parameter is expected to be a examples/project-name
if [ $# -lt 1 ]; then
    echo "Usage: $0 <examples/directory_name>"
    exit 1
else
    THIS_EXAMPLE="$1"
fi

# make sure the provided parameter directory exists
if [ ! -d "$THIS_EXAMPLE" ]; then
    echo "Directory not found: $THIS_EXAMPLE"
    exit 1
fi
# we impose a requirement to have a sdkconfig.defaults file
if [ ! -e "$THIS_EXAMPLE/sdkconfig.defaults" ]; then
    echo "File not found: $THIS_EXAMPLE/sdkconfig.defaults"
    exit 1
fi

# check if IDF_PATH is set
if [ -z "$IDF_PATH" ]; then
    echo "Please follow the instruction of ESP-IDF installation and set IDF_PATH."
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

# Ready to build; prep.
pushd "$THIS_EXAMPLE"

export NEED_YML_RESTORE=
if [ -e "./main/idf_component.yml" ]; then
    echo "Temporarily disabling ESP Component by renaming idf_component.yml"
    mv ./main/idf_component.yml ./main/idf_component.yml.bak
    export NEED_YML_RESTORE=Y
fi

export NEED_DIR_RESTORE=
if [ -e "./managed_components" ]; then
    echo "Temporarily renaming managed_components"
    mv ./managed_components ./managed_components.bak
    export NEED_DIR_RESTORE=Y
fi

#**************************************************************************************************
# Build
#**************************************************************************************************
# put in a woldSSL component directory to act like the managed component published version
cp -r ../../lib/components ./

idf.py build
THIS_ERROR_CODE=$?

rm -r ./components/

#**************************************************************************************************
# Restore managed components
#**************************************************************************************************
if [ "${NEED_YML_RESTORE^}" == "Y" ]; then
    echo "Restoring ./main/idf_component.yml"
    mv ./main/idf_component.yml.bak ./main/idf_component.yml
fi

if [ "${NEED_DIR_RESTORE^}" == "Y" ]; then
    echo "Restoring ./managed_components"
    mv ./managed_components.bak ./managed_components
fi

popd

#**************************************************************************************************
# Done
#**************************************************************************************************

if [ $THIS_ERROR_CODE -ne 0 ]; then
    echo ""
    echo "Failed to build"
    exit 1
else
    echo ""
    echo "Build successful."
    echo ""
fi
