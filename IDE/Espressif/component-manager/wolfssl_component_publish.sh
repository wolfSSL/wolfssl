#!/bin/bash
#
# wolfssl_component_publish.sh
#
# Script to publish wolfSSL to Espressif ESP Registry.
# This file is not needed by end users.
#


#**************************************************************************************************
# A function to copy a given wolfSSL root: $1
# for a given subdirectory: $2
# for a file type specification: $3
# optionally append files with: $4
#
# Example: copy wolfssl/src/*.c to the local ./src directory:
#   copy_wolfssl_source /workspace/wolfssl  "src"  "*.c"
#
# Files in this local directory, typically called "component-manager"
# will be published to the Espressif ESP Registry.
#
# Contents of $dst will be DELETED unless $4 == "APPEND"
copy_wolfssl_source() {
  local src="$1"
  local dst="$2"
  local file_type="$3"
  local append="$4"

  # uncomment for verbose output:
  # echo ""
  # echo "Copying files: $file_type"

  if [[ -d "$dst" && "$append" != "APPEND" ]]; then
    # uncomment for verbose output:
    # echo "Deleting files in directory: $dst"
    find "$dst" -type f -delete
  fi

  # uncomment for verbose output:
  # echo "Copying files from $src/$dst to $(pwd)/$dst"
  mkdir -p "$dst"

  if find "$src"/"$dst" -type f -name "$file_type" -print -quit | grep -q '^'; then
      # uncomment for verbose output:
      # echo "cp -u $src/$dst/$file_type ./$dst/"
              cp -u "$src"/"$dst"/$file_type "./$dst/"
      echo "Copied $dst/$file_type"
  else
    echo "ERROR: Not Found: $dst"
  fi
}

#**************************************************************************************************
#**************************************************************************************************
# Begin script
#**************************************************************************************************
#**************************************************************************************************

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

# check if IDF_COMPONENT_API_TOKEN is set
if [ -z "IDF_COMPONENT_API_TOKEN" ]; then
    echo "Please follow the instructions and set IDF_COMPONENT_API_TOKEN."
    exit 1
fi

THIS_VERSION=$(grep "version:" ./idf_component.yml | awk -F'"' '{print $2}')
if [ -z "$THIS_VERSION" ]; then
    echo "Quoted version: value not found in ./idf_component.yml"
    exit 1
fi

FOUND_LOCAL_DIST=
if [ -f "./dist/wolfssl_$THIS_VERSION.tgz" ]; then
    echo "Found file wolfssl_$THIS_VERSION.tgz"
    echo "Duplicate versions cannot be published. By proceeding, you will overwrite the local source."
    echo ""
    FOUND_LOCAL_DIST=true
fi

if [ -d "./dist/wolfssl_$THIS_VERSION" ]; then
    echo "Found directory: wolfssl_$THIS_VERSION"
    echo "Duplicate versions cannot be published. By proceeding, you will overwrite the local source."
    echo ""
    FOUND_LOCAL_DIST=true
fi

if [ -z "$FOUND_LOCAL_DIST" ]; then
    echo "Confirmed a prior local distribution file set does not exist for wolfssl_$THIS_VERSION."
else
    OK_TO_OVERWRITE_DIST=
    until [ "${OK_TO_OVERWRITE_DIST^}" == "Y" ] || [ "${OK_TO_OVERWRITE_DIST^}" == "N" ]; do
        read -n1 -p "Proceed? (Y/N) " OK_TO_OVERWRITE_DIST
        OK_TO_OVERWRITE_DIST=${OK_TO_OVERWRITE_DIST^};
        echo;
    done

    if [ "${OK_TO_OVERWRITE_DIST^}" == "Y" ]; then
        echo ""
        echo "Proceeding. Choosing to publish will OVERWRITE EXISTING DISTRIBUTION..."
        echo ""
    else
        echo "Exiting..."
        exit 1
    fi
fi


echo ""
echo "Publishing local wolfSSL source to ESP Registry: components.espressif.com"
echo ""
echo "WARNING: The live wolfSSL will be replaced upon completion."
echo ""
echo "Current source directory:"
echo ""
pwd
echo ""
echo "Version to publish in local idf_component.yml (version numbers cannot be reused!)"
echo ""
grep "version:" idf_component.yml
echo ""

#**************************************************************************************************
# copy all source files related to the ESP Component Registry
#**************************************************************************************************

# This script is expecting to be in wolfssl/IDE/Espressif/component-manager
# The root of wolfssl is 3 directories up:
THIS_WOLFSSL=$(dirname "$(dirname "$(dirname "$PWD")")")

# Optionally specify an alternative source of wolfSSL to publish:

# TODO REMOVE
THIS_WOLFSSL=/mnt/c/test/wolfssl-master

# END TODO REMOVE

# copy_wolfssl_source $THIS_WOLFSSL
echo "Copying source from $THIS_WOLFSSL"
echo $(cd /mnt/c/test/wolfssl-master && git status)
#**************************************************************************************************
# Confirm we actually want to proceed to copy.
#**************************************************************************************************
OK_TO_COPY=
until [ "${OK_TO_COPY^}" == "Y" ] || [ "${OK_TO_COPY^}" == "N" ]; do
    read -n1 -p "Proceed? (Y/N) " OK_TO_COPY
    OK_TO_COPY=${OK_TO_COPY^};
    echo;
done

if [ "${OK_TO_COPY^}" == "Y" ]; then
    echo "Proceeding to copy..."
else
    echo "Exiting..."
    exit 1
fi

cp                  $THIS_WOLFSSL/README.md   ./README.md

# strip any HTML anchor tags, that are irrelevant and don't look pretty
echo "Removing HTML anchor tags from README..."
sed -i '/<a href/,/<\/a>/d' ./README.md

if [ -e "./README_REGISTRY_PREPEND.md" ]; then
    echo "Pre-pending README_REGISTRY_PREPEND to README.md"
    cat ./README_REGISTRY_PREPEND.md  ./README.md > ./NEW_README.md
    THIS_ENCODING=$(file -b --mime-encoding ./NEW_README.md)
    echo "Found encoding: $THIS_ENCODING"

    iconv  --to-code=UTF-8//ignore  --output=./README.md  "./NEW_README.md"
    THIS_ERROR_CODE=$?

    if [ $THIS_ERROR_CODE -ne 0 ]; then
        echo ""
        echo "Warning! Bad encoding in README.md file. Removing bad chars and converting to UTF-8"
        iconv  --to-code=UTF-8//ignore -c  --output=./README.md "./NEW_README.md"
    else
        echo ""
        echo "Confirmed README.md contains no bad encoding chars."
        echo ""
    fi
else
    echo "ERROR: README_REGISTRY_PREPEND.md not found to prepend to README.md"
    exit 1
fi

# Ensure there's a comment in the README.md for this specific version being published!
#
# grep "version:" idf_component.yml
#   will typically return a value such as:  version: "1.0.7-dev"
#
# we'll want to look for the 1.0.7-dev part in the README.md
#

echo "Checking README.md for Version $THIS_VERSION"
grep "$THIS_VERSION" README.md
THIS_ERROR_CODE=$?

if [ $THIS_ERROR_CODE -ne 0 ]; then
    echo ""
    echo "Version text not found in the README.md file. Please edit and try again."
    exit 1
else
    echo ""
    echo "Confirmed README.md contains the version text: $THIS_VERSION"
    echo ""
fi

# We need a user_settings.h in the include directory,
# However we'll keep a default Espressif locally, and *not* copy here:
#
# copy_wolfssl_source $THIS_WOLFSSL  "include"                           "*.h"
#
# See also IDE/Espressif/ESP-IDF/user_settings.h


# Copy C source files
copy_wolfssl_source  $THIS_WOLFSSL  "src"                                "*.c"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/src"                      "*.c"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/benchmark"                "*.c"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/src/port/atmel"           "*.c"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/src/port/Espressif"       "*.c"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/test"                     "*.c"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/user-crypto/src"          "*.c"

# Copy C header files
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/benchmark"                "*.h"  APPEND
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/test"                     "*.h"  APPEND
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/user-crypto/include"      "*.h"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfssl"                            "*.h"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfssl/openssl"                    "*.h"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfssl/wolfcrypt"                  "*.h"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfssl/wolfcrypt/port/atmel"       "*.h"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfssl/wolfcrypt/port/Espressif"   "*.h"

# Note that for examples, the ESP Registry will append the these README files to
# the main README.md at publish time, and generate achor text hyperlinks.
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/benchmark"                "README.md"  APPEND
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/test"                     "README.md"  APPEND

#**************************************************************************************************
# make sure the version found in ./wolfssl/version.h matches  that in ./idf_component.yml
#**************************************************************************************************
if [ -e "./wolfssl/version.h" ]; then
    WOLFSSL_VERSION=$(grep "LIBWOLFSSL_VERSION_STRING" ./wolfssl/version.h | awk '{print $3}' | tr -d '"')
    grep "$WOLFSSL_VERSION" ./idf_component.yml
    THIS_ERROR_CODE=$?
    if [ $THIS_ERROR_CODE -ne 0 ]; then
        echo ""
        echo "Version text in idf_component.yml does not match ./wolfssl/version.h ($WOLFSSL_VERSION). Please edit and try again."
        # optionally exit
        # exit 1
    else
        echo ""
        echo "Confirmed idf_component.yml matches ./wolfssl/version.h the version text: $WOLFSSL_VERSION"
        echo ""
    fi
else
    echo "ERROR: ./wolfssl/version.h not found"
    exit 1
fi

#**************************************************************************************************
# All files from the wolfssl/IDE/Espressif/ESP-IDF/examples
# directory that contain the text: __ESP_COMPONENT_SOURCE__
# will be copied to the local ESP Registry ./examples/ directory
echo "Copying __ESP_COMPONENT_SOURCE__ tagged files..."

# go to the root of the Espressif examples
export PUB_CURRENT_PATH=$(pwd)
echo Current Path saved: $PUB_CURRENT_PATH

cd ../../Espressif/ESP-IDF/examples

echo "Copying example sample files tagged with __ESP_COMPONENT_SOURCE__ from:"
echo ""
pwd
echo ""

echo "Found example [source] files to copy to [destination]:"
echo ""
find ./ -type f -not -path "*/build/*" -exec grep -l "__ESP_COMPONENT_SOURCE__" {} + | xargs -I {} echo {}   ../../component-manager/examples/{}

# The cp command seems to not like creating a directory struture, even with --parents
# so we create the directory in advance:
echo "Creating directories in destination..."
find ./ -type f -not -path "*/build/*" -exec grep -l "__ESP_COMPONENT_SOURCE__" {} + | xargs -I {} sh -c 'mkdir --parents ../../component-manager/examples/"$(dirname {})"'
find ../../component-manager/examples/ -type d

# This is the same as the "Found example [source]" above, but copying instead just displaying:
echo Copying files...
find ./ -type f -not -path "*/build/*" -exec grep -l "__ESP_COMPONENT_SOURCE__" {} + | xargs -I {} cp   {}   ../../component-manager/examples/{}
#
#**************************************************************************************************

cd "$PUB_CURRENT_PATH"
echo "Returned to path:"
pwd

# Check to see if we failed to previously build:
if [ -e "./build_failed.txt" ]; then
    echo "Removing semaphore file: build_failed.txt"
    rm ./build_failed.txt
fi

# TODO remove
# Files known to need attention
cp ./lib/user_settings.h ./include/user_settings.h
cp ./lib/esp32-crypt.h   ./wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h



#**************************************************************************************************
# Build all the projects in ./examples/
# if an error is encountered, create a semaphore file called build_failed.txt
#
# NOTE: this checks if the *current* examples build with the *CURRENT* (already published) ESP Registry version.
# Run this script a second time (don't publish) to ensure the examples build with freshly-published wolfSSL code.
# Reminder that there may be a delay of several minutes or more between the time of publish, and the time
# when the files are actually available.

# TODO this build is for the *prior* version
# find  ./examples/ -maxdepth 1 -mindepth 1 -type d | xargs -I {} sh -c 'cd {} && echo "\n\nBuilding {} for minimum component version: " && grep "wolfssl/wolfssl:" main/idf_component.yml && echo "\n\n" && idf.py build || touch ../../build_failed.txt'

# Check to see if we failed on this build:
if [ -e "./build_failed.txt" ]; then
    echo "Build failed!"
    exit 1
fi
#**************************************************************************************************

# Delete any managed components and build directories before uploading.
# The files *should* be excluded by default, so this is just local housekeeping.
# if not excluded, the upload will typically be 10x larger. Expected size = 10MB.
echo "Removing managed_components and build directories:"
find  ./examples/ -maxdepth 1 -mindepth 1 -type d | xargs -I {} rm -r {}/managed_components/
find  ./examples/ -maxdepth 1 -mindepth 1 -type d | xargs -I {} rm -r {}/build/

echo ""
echo "Samples file to publish:"
echo ""
find ./examples/
echo ""

echo "Ready to publish..."

if [ "${OK_TO_OVERWRITE_DIST^}" == "Y" ]; then
    echo ""
    echo "  WARNING: The local distribution files have been updated."
    echo ""
    echo "  By proceeding, you confirm this version has not been previously published."
    echo ""
    echo "  If this version has been published, you will likely see an error when proceeding."
    echo ""
fi

echo ""
grep "version:" idf_component.yml
echo ""

#**************************************************************************************************
# Confirm we actually want to proceed to publish.
#**************************************************************************************************
COMPONENT_MANAGER_PUBLISH=
until [ "${COMPONENT_MANAGER_PUBLISH^}" == "Y" ] || [ "${COMPONENT_MANAGER_PUBLISH^}" == "N" ]; do
    read -n1 -p "Proceed? (Y/N) " COMPONENT_MANAGER_PUBLISH
    COMPONENT_MANAGER_PUBLISH=${COMPONENT_MANAGER_PUBLISH^};
    echo;
done

if [ "${COMPONENT_MANAGER_PUBLISH}" == "Y" ]; then
    echo;
    echo "Here we go!"
    echo ""
    pwd
    echo ""
    echo "Creating files in ./dist/ then creating .tgz to upload. Please be patient..."
    #
    # The component will be called "wolfssl__wolfssl". There's no way to change that at this time.
    # Unfortunately, there is no way to change the build-system name of a dependency installed
    # by the component manager. It's always `namespace__component`.
    #
    echo "compote component upload --namespace wolfssl --name wolfssl"
          compote component upload --namespace wolfssl --name wolfssl

    echo ""
    echo "View the new component at https://components.espressif.com/components/wolfssl/wolfssl"
    echo ""
    echo "Done!"
    echo ""
else
    echo;
    echo "No files published!"
fi
