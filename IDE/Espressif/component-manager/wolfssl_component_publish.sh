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
      # this gives a shellcheck warning:
      # cp -u "$src"/"$dst"/$file_type "./$dst/"
      #
      # this does not work: (gives cp: cannot stat .. No such file or directory)
      # cp -u "$src"/"$dst"/""$file_type" "./$dst/"
      #
      # so we'll assemble a local command var:
      local cp_command="cp -u $src/$dst/$file_type ./$dst/"
      # uncomment for verbose output:
      echo "Executing command: $cp_command"
      eval "$cp_command"
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
if [ -z "$IDF_COMPONENT_API_TOKEN" ]; then
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
        read -r -n1 -p "Proceed? (Y/N) " OK_TO_OVERWRITE_DIST
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

# TODO REMOVE this line if not using /test/wolfssl-master

THIS_WOLFSSL=/mnt/c/test/wolfssl-master

# END TODO REMOVE

# copy_wolfssl_source $THIS_WOLFSSL
echo "Copying source from $THIS_WOLFSSL"

pushd "$THIS_WOLFSSL" || exit 1
git status
popd || exit 1

#**************************************************************************************************
# Confirm we actually want to proceed to copy.
#**************************************************************************************************
OK_TO_COPY=
until [ "${OK_TO_COPY^}" == "Y" ] || [ "${OK_TO_COPY^}" == "N" ]; do
    read -r -n1 -p "Proceed? (Y/N) " OK_TO_COPY
    OK_TO_COPY=${OK_TO_COPY^};
    echo;
done

if [ "${OK_TO_COPY^}" == "Y" ]; then
    echo "Proceeding to copy..."
else
    echo "Exiting..."
    exit 1
fi

#**************************************************************************************************
# Copy root README.md file, clean it, and prepend README_REGISTRY_PREPEND.md text
#**************************************************************************************************
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
echo "Copying C Source files... $THIS_WOLFSSL"
copy_wolfssl_source  $THIS_WOLFSSL  "src"                                '*.c'
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/src"                      '*.c'
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/benchmark"                '*.c'
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/src/port/atmel"           "*.c"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/src/port/Espressif"       "*.c"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/test"                     "*.c"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/user-crypto/src"          "*.c"

# Copy C header files
echo "Copying C Header files..."
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/benchmark"                "*.h"  APPEND
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/test"                     "*.h"  APPEND
copy_wolfssl_source  $THIS_WOLFSSL  "wolfcrypt/user-crypto/include"      "*.h"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfssl"                            "*.h"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfssl/openssl"                    "*.h"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfssl/wolfcrypt"                  "*.h"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfssl/wolfcrypt/port/atmel"       "*.h"
copy_wolfssl_source  $THIS_WOLFSSL  "wolfssl/wolfcrypt/port/Espressif"   "*.h"

# Note that for example apps, the ESP Registry will append the these README files to
# the main README.md at publish time, and generate anchor text hyperlinks.
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
        # optionally exit TODO?

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
# will be copied to the local ESP Registry ./examples/ directory




# Define the source directory and destination directory.
# We start in           IDE/Espressif/component-manager
# We want examples from IDE/Espressif/ESP-IDF/examples
source_dir="../ESP-IDF/examples"

# We'll copy examples to publish into our local examples
# We start in           IDE/Espressif/component-manager
# Copy example files to IDE/Espressif/component-manager/examples
destination_dir="examples"

# Check if the destination directory exists, and create it if it doesn't
if [ ! -d "$destination_dir" ]; then
    mkdir -p "$destination_dir"
fi

MISSING_FILES=N
# Read the list of files from component_manifest.txt and copy them
while IFS= read -r file_path; do

    if [[ "$file_path" == "#"* ]]; then
        echo "$file_path"
    else
        # Remove leading and trailing whitespace from the file path
        file_path=$(echo "$file_path" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

        # Check if the file path is empty (blank line)
        if [ -z "$file_path" ]; then
            continue
        fi

        # Construct the full source and destination paths
        full_source_path="$source_dir/$file_path"
        full_destination_path="$destination_dir/$file_path"

        # Create the directory structure in the destination if it doesn't exist
        mkdir -p "$(dirname "$full_destination_path")"

        # Copy the file to the destination
        cp "$full_source_path" "$full_destination_path"
        THIS_ERROR_CODE=$?
    if [ $THIS_ERROR_CODE -eq 0 ]; then
        echo "Copied: $full_source_path -> $full_destination_path"
    else
        MISSING_FILES=Y
        # echo "WARNING: File not copied:  $full_source_path"
    fi


    fi
done < "component_manifest.txt"

#**************************************************************************************************
# Check if we detected any missing example files that did not successfully copy.
#**************************************************************************************************
if [ "${MISSING_FILES^}" == "Y" ]; then
    echo "Some example files not copied. Continue?"
    #**************************************************************************************************
    # Confirm we actually want to proceed to publish if there were missing example source files.
    #**************************************************************************************************
    COMPONENT_MANAGER_CONTINUE=
    until [ "${COMPONENT_MANAGER_CONTINUE^}" == "Y" ] || [ "${COMPONENT_MANAGER_CONTINUE^}" == "N" ]; do
        read -r -n1 -p "Proceed? (Y/N) " COMPONENT_MANAGER_CONTINUE
        COMPONENT_MANAGER_CONTINUE=${COMPONENT_MANAGER_CONTINUE^};
        echo;
    done

    if [ "${COMPONENT_MANAGER_CONTINUE}" == "Y" ]; then
        echo "Continuing with missing files"
    else
        echo "Exiting..."
        exit 1
    fi
fi

echo "Copy operation completed for examples."

# Check to see if we failed to previously build:
if [ -e "./build_failed.txt" ]; then
    echo "Removing semaphore file: build_failed.txt"
    rm ./build_failed.txt
fi

# TODO remove
# Files known to need attention
# The current examples expect user_settings in the root include directory
# this can be removed once subsequent PR updates are accepted for examples
cp ./lib/user_settings.h ./include/user_settings.h

# The component registry needs a newer version of esp32-crypt.h
cp ./lib/esp32-crypt.h   ./wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h
# End TODO


#**************************************************************************************************
# Build all the projects in ./examples/
# if an error is encountered, create a semaphore file called build_failed.txt
#
# NOTE: this checks if the *current* examples build with the *CURRENT* (already published) ESP Registry version.
# Run this script a second time (don't publish) to ensure the examples build with freshly-published wolfSSL code.
# Reminder that there may be a delay of several minutes or more between the time of publish, and the time
# when the files are actually available.

# TODO this build is for the *prior* version of ESP Component (the one *already* published)
# find  ./examples/ -maxdepth 1 -mindepth 1 -type d | xargs -I {} sh -c 'cd {} && echo "\n\nBuilding {} for minimum component version: " && grep "wolfssl/wolfssl:" main/idf_component.yml && echo "\n\n" && idf.py build || touch ../../build_failed.txt'

# we'll do a test build of the current to-be-published version of wolfSSL
find  ./examples/ -maxdepth 1 -mindepth 1 -type d | xargs -I {} sh -c 'echo "\n\nBuilding {} " && ./wolfssl_build_example.sh {} || touch ../../build_failed.txt'

echo ""
echo "Warning: build check for examples not yet in place."
echo ""

# Check to see if we failed on this build:
if [ -e "./build_failed.txt" ]; then
    echo "Build failed!"
    exit 1
fi
#**************************************************************************************************

# Delete any managed components and build directories before uploading.
# The files *should* be excluded by default, so this is just local housekeeping.
# if not excluded, the upload will typically be 10x larger. Expected size = 10MB.
echo "Removing managed_components and build directories: (errors ok here)"
find  ./examples/ -maxdepth 1 -mindepth 1 -type d -print0 | xargs -0 -I {} rm -r {}/managed_components/
find  ./examples/ -maxdepth 1 -mindepth 1 -type d -print0 | xargs -0 -I {} rm -r {}/build/

echo ""
echo "Samples file to publish:"
echo ""
find ./examples/ -print
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
    read -r -n1 -p "Proceed? (Y/N) " COMPONENT_MANAGER_PUBLISH
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

    # upload command is currently disabled during testing:
## disabled          compote component upload --namespace wolfssl --name wolfssl

    echo ""
    echo "View the new component at https://components.espressif.com/components/wolfssl/wolfssl"
    echo ""
    echo "Done!"
    echo ""
else
    echo;
    echo "No files published!"
fi
