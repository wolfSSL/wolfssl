#!/bin/bash
#
# wolfssl_component_publish.sh [optional directory source to publish]
#
# Script to publish wolfSSL, wolfMQTT, and wolfSSH to Espressif ESP Registry.
# This file is duplicated across repositories. It is not needed by end users.
#
#                              NOTICE
#
#       ***** PRODUCTION DEPLOYMENT MUST BE MANUALLY ENABLED *****
#
#    export $IDF_COMPONENT_REGISTRY_URL=https://components.espressif.com
#
# Version:  1.0
#
# For usage, see INSTALL.md
#
# TODO: config file settings not yet supported here. See:
# https://docs.espressif.com/projects/idf-component-manager/en/latest/guides/packaging_components.html#authentication-with-a-config-file
#
# set our known production and staging links. No trailing "/" char. Edit with caution:
export PRODUCTION_URL="https://components.espressif.com"
export STAGING_URL="https://components-staging.espressif.com"

# Unlike the default operation, is not explicitly set to production
# we assume the publish is staging.
echo "--------------------------------------------------------------------------------------------"
if [ -z "$IDF_COMPONENT_REGISTRY_URL" ]; then
    export IDF_COMPONENT_REGISTRY_URL="$STAGING_URL"
    echo "Setting default publishing location to ESP Registry: $STAGING_URL"
    echo ""
fi

#**************************************************************************************************
# copy_wolfssl_source()
#
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
} # copy_wolfssl_source()

#**************************************************************************************************
#
# The first parameter, when present, is expected to be the path to the component to install:
#
#       wolfssl_component_publish.sh  /mnt/c/workspace/wolfssl-master
#
# The only acceptable names MUST contain the component name. (e.g. don't clone wolfssl into OtherName)
#
# Source directory names may contain a "-" delimiter: (e.g. wolfssl-username, wolfssl-master)
#
# If a parameter is not specified, this script is expected to be in [repo]/IDE/Espressif/component-manager
#
#    e.g. /some/directory/path/wolfssl/IDE/Espressif/component-manager:
#
#    The root to publish is 3 directories up from `component-manager` in `wolfssl`.
#
if [ $# -lt 1 ]; then
    # This script directory is the source, assumed 3 levels down:
    THIS_DIRECTORY_PARAMETER=$(dirname "$(dirname "$(dirname "$PWD")")")
else
    # If a parameter was supplied, we'll use that, instead.
    THIS_DIRECTORY_PARAMETER="$1"
fi

# Whether specified or inferred, the directory must exist to proceed.
if [ ! -d "$THIS_DIRECTORY_PARAMETER" ]; then
    echo "Directory Parameter doesn't exist.: $THIS_DIRECTORY_PARAMETER"
    exit 1
fi

echo "Source to publish:  $THIS_DIRECTORY_PARAMETER"
# get the directory name, e.g. wolfssl-master
COMPONENT_NAME_GUESS=$(basename "$THIS_DIRECTORY_PARAMETER")

# Set the in field separator to "-"
IFS="-"

# Read the directory name into an array. We only want the first part (e.g. wolfssl)
read -r -a COMPONENT_GUESS_PARTS <<< "$COMPONENT_NAME_GUESS"

# Get just the wolfssl part if "wolfssl-username"
export THIS_DIRECTORY_COMPONENT="${COMPONENT_GUESS_PARTS[0]}"

# Regardless of source text, we want lower case name components.
export THIS_DIRECTORY_COMPONENT="${THIS_DIRECTORY_COMPONENT,,}"

echo "THIS_DIRECTORY_COMPONENT = $THIS_DIRECTORY_COMPONENT"

# Need to set IFS if using it elsewhere:
IFS=

#**************************************************************************************************
#**************************************************************************************************
# Begin script
#**************************************************************************************************
#**************************************************************************************************
#
# Reminder this script may be running from a development repo, but publishing source code from a
# *different* specified directory (see above). However, the GitHub component name must match.
# For example, if we are in `wolfMQTT-username`, we must only publish the wolfmqtt component.
echo "Searching for component name (this script must run in a github repo directory)"
THIS_COMPONENT_CONFIG="$(git config --get remote.origin.url)"
export THIS_COMPONENT
THIS_COMPONENT="$(basename -s .git "$THIS_COMPONENT_CONFIG")" || exit 1

# Our component names are all lower case, regardless of repo name:
THIS_COMPONENT="${THIS_COMPONENT,,}"

# Check that we actually found a repository component name.
if [ -z "$THIS_COMPONENT" ]; then
    echo "Could not find component name."
    echo "Please run this script from a github repo directory."
    exit 1
else
    echo "Found component to publish: $THIS_COMPONENT"
fi

# Check that this repo and the source directory are for the same component name
if [ "$THIS_COMPONENT" == "$THIS_DIRECTORY_COMPONENT" ]; then
    echo "Will publish $THIS_COMPONENT from $THIS_DIRECTORY_PARAMETER"
else
    echo "ERROR: Not a $THIS_COMPONENT component in $THIS_DIRECTORY_PARAMETER"
    exit 1
fi

export THIS_SOURCE="$THIS_DIRECTORY_PARAMETER"

# Define the source directory and destination directory.
# We start in           IDE/Espressif/component-manager
# We want examples from IDE/Espressif/ESP-IDF/examples
#
# EXAMPLE_SOURCE_DIR="$THIS_SOURCE/IDE/Espressif/ESP-IDF/examples"

export EXAMPLE_SOURCE_DIR="missing"

case "$THIS_COMPONENT" in
    "wolfssl")
        export COMPONENT_VERSION_STRING="LIBWOLFSSL_VERSION_STRING"
        export EXAMPLE_SOURCE_DIR="$THIS_SOURCE/IDE/Espressif/ESP-IDF/examples"
        ;;
    "wolfssh")
        export COMPONENT_VERSION_STRING="LIBWOLFSSH_VERSION_STRING"
        export EXAMPLE_SOURCE_DIR="$THIS_SOURCE/ide/Espressif/ESP-IDF/examples"
        ;;
    "wolfmqtt")
        export COMPONENT_VERSION_STRING="LIBWOLFMQTT_VERSION_STRING"
        export EXAMPLE_SOURCE_DIR="$THIS_SOURCE/IDE/Espressif/ESP-IDF/examples"
        ;;
    *)
    export COMPONENT_VERSION_STRING=""
    echo "Not a supported component: $THIS_COMPONENT"
    exit 1
    ;;
esac

# check if there's an unsupported idf_component_manager.yml file.
if [ -e "./idf_component_manager.yml" ]; then
    # There may be contradictory settings in idf_component_manager.yml vs environment variables,
    # Which takes priority? Check not performed at this time.
    echo "ERROR: This script does not yet support idf_component_manager.yml."
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

# check if IDF_COMPONENT_API_TOKEN is set
if [ -z "$IDF_COMPONENT_API_TOKEN" ]; then
    echo "Please follow the instructions and set IDF_COMPONENT_API_TOKEN value."
    exit 1
fi

# there needs to be a version in the yml file
THIS_VERSION=$(grep "version:" ./idf_component.yml | awk -F'"' '{print $2}')
if [ -z "$THIS_VERSION" ]; then
    echo "Quoted version: value not found in ./idf_component.yml"
    exit 1
fi

# We need to have determined the published name before getting here (e.g. if called mywolfssl for staging)
if [ "$IDF_COMPONENT_REGISTRY_URL" == "$PRODUCTION_URL" ]; then
    echo "WARNING: The live $THIS_COMPONENT will be replaced upon completion."
    echo ""
    export THIS_NAMESPACE=wolfssl
    export THIS_COMPONENT_NAME="$THIS_COMPONENT"
else
    if [ "$IDF_COMPONENT_REGISTRY_URL" == "$STAGING_URL" ]; then
        # check if USER is set
        if [ -z "$USER" ]; then
            echo "Could not detect USER environment variable needed for staging"
            exit 1
        fi
        export THIS_NAMESPACE="$USER"
        export THIS_COMPONENT_NAME="my$THIS_COMPONENT"
        echo ""
        echo "WARNING: The staging $THIS_COMPONENT_NAME component will be replaced upon completion:"
        echo ""
        echo "   $IDF_COMPONENT_REGISTRY_URL/components/$THIS_NAMESPACE/$THIS_COMPONENT_NAME"
        echo ""
    else
        echo ""
        echo "WARNING: unexpected IDF_COMPONENT_REGISTRY_URL value = $IDF_COMPONENT_REGISTRY_URL"
        echo "Expected blank or $STAGING_URL or $PRODUCTION_URL"
        exit 1
    fi
fi

# check if prior version tgz file already published.
FOUND_LOCAL_DIST=
if [ -f "./dist/${THIS_COMPONENT_NAME}_${THIS_VERSION}.tgz" ]; then
    echo "Found file ${THIS_COMPONENT_NAME}_${THIS_VERSION}.tgz"
    echo "Duplicate versions cannot be published. By proceeding, you will overwrite the local source."
    echo ""
    FOUND_LOCAL_DIST=true
fi

# check if prior version directory already published
if [ -d "./dist/${THIS_COMPONENT_NAME}_${THIS_VERSION}" ]; then
    echo "Found directory: ${THIS_COMPONENT_NAME}_${THIS_VERSION}"
    echo "Duplicate versions cannot be published. By proceeding, you will overwrite the local source."
    echo ""
    FOUND_LOCAL_DIST=true
fi

# check if this version distribution already exists, and if so, if it should be overwritten
if [ -z "$FOUND_LOCAL_DIST" ]; then
    echo "Confirmed a prior local distribution file set does not exist for ${THIS_COMPONENT_NAME}_${THIS_VERSION}."
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


#**************************************************************************************************
# Show Ready Summary before step that will copy all source files related to the ESP Component Registry
#**************************************************************************************************
echo ""


echo "--------------------------------------------------------------------------------------------"
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

# Optionally specify an alternative source of wolfSSL to publish:

# TODO REMOVE this line if not using /test/wolfssl-master

# if [ "wolfmqtt" == "$THIS_COMPONENT" ]; then
#     THIS_SOURCE=/mnt/c/workspace/wolfMQTT-master
# else
#     if [ "wolfssl" == "$THIS_COMPONENT" ]; then
#         THIS_SOURCE=/mnt/c/workspace/wolfssl-master
#     else
#         if [ "wolfssh" == "$THIS_COMPONENT" ]; then
#             THIS_SOURCE=/mnt/c/workspace/wolfssh-master
#         else
#             echo "Error: not a supported component: $THIS_COMPONENT"
#             exit 1
#         fi
#     fi
# fi
# END TODO REMOVE

# copy_wolfssl_source $THIS_SOURCE
echo "------------------------------------------------------------------------"
echo "Copying source to publish from $THIS_SOURCE"
echo "------------------------------------------------------------------------"
echo ""
echo "git status:"
pushd "$THIS_SOURCE" || exit 1
git status
popd || exit 1

#**************************************************************************************************
# Confirm we actually want to proceed to copy.
#**************************************************************************************************
echo "Existing component-manager/examples files will be deleted and copied from $EXAMPLE_SOURCE_DIR"
OK_TO_COPY=
until [ "${OK_TO_COPY^}" == "Y" ] || [ "${OK_TO_COPY^}" == "N" ]; do
    read -r -n1 -p "Proceed? (Y/N) " OK_TO_COPY
    OK_TO_COPY=${OK_TO_COPY^};
    echo;
done

echo ""

if [ "${OK_TO_COPY^}" == "Y" ]; then
    echo "Proceeding to copy..."
else
    echo "Exiting..."
    exit 1
fi

#**************************************************************************************************
# Copy root README.md file, clean it, and prepend README_REGISTRY_PREPEND.md text.
# Also prepend a staging note as appropriate.
#**************************************************************************************************
# Copy a fresh repository source README.md
cp  "$THIS_SOURCE/README.md"  ./README.md

# strip any HTML anchor tags, that are irrelevant and don't look pretty
echo "Removing HTML anchor tags from README..."
sed -i '/<a href/,/<\/a>/d' ./README.md

if [ -e "./README_REGISTRY_PREPEND.md" ]; then
    if [ "$IDF_COMPONENT_REGISTRY_URL" == "$STAGING_URL" ]; then
        echo "Prepend README_STAGING_PREPEND.md and README_REGISTRY_PREPEND.md to README.md"
        cat ./README_STAGING_PREPEND.md ./README_REGISTRY_PREPEND.md  ./README.md  >  ./NEW_README.md
    else
    echo "Prepend README_REGISTRY_PREPEND.md to README.md"
        cat                             ./README_REGISTRY_PREPEND.md  ./README.md  >  ./NEW_README.md
    fi
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
    echo "  See file: README_REGISTRY_PREPEND.md that is used to create README.md"
    exit 1
else
    echo ""
    echo "Confirmed README.md contains the version text: $THIS_VERSION"
    echo ""
fi

# We need a user_settings.h in the include directory,
# However we'll keep a default Espressif locally, and *not* copy here:
#
# copy_wolfssl_source $THIS_SOURCE  "include"                           "*.h"
#
# See also IDE/Espressif/ESP-IDF/user_settings.h
#
#**************************************************************************************************
# Copy C source files
# Reminder: each component must specify a value for EXAMPLE_SOURCE_DIR (above)
#**************************************************************************************************

# wolfMQTT Files
if [ "wolfmqtt" == "$THIS_COMPONENT" ]; then

    echo "Copying wolfMQTT C Source files... $THIS_SOURCE"
    copy_wolfssl_source  "$THIS_SOURCE"  "src"                                "*.c"

    # Copy C header files
    echo "Copying wolfMQTT C Header files..."
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfmqtt"                           "*.h"

    # wolfMQTT looks for an options.h file
    echo "Copying wolfMQTT options.h"
    cp ./lib/options.h "./wolfmqtt/options.h"
fi

# wolfSSH Files
if [ "wolfssh" == "$THIS_COMPONENT" ]; then
    echo "Copying wolfSSH C Source files... $THIS_SOURCE"
    copy_wolfssl_source  "$THIS_SOURCE"  "src"                                "*.c"

    # Copy C header files
    echo "Copying wolfSSH C Header files..."
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfssh"                           "*.h"
fi

# wolfSSL Files
if [ "wolfssl" == "$THIS_COMPONENT" ]; then

    echo "Copying wolfSSL C Source files... $THIS_SOURCE"
    copy_wolfssl_source  "$THIS_SOURCE"  "src"                                "*.c"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/src"                      "*.c"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/benchmark"                "*.c"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/src/port/atmel"           "*.c"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/src/port/Espressif"       "*.c"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/test"                     "*.c"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/user-crypto/src"          "*.c"

    # Copy C header files
    echo "Copying wolfSSL C Header files..."
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/benchmark"                "*.h"  APPEND
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/test"                     "*.h"  APPEND
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/user-crypto/include"      "*.h"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfssl"                            "*.h"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfssl/openssl"                    "*.h"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfssl/wolfcrypt"                  "*.h"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfssl/wolfcrypt/port/atmel"       "*.h"
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfssl/wolfcrypt/port/Espressif"   "*.h"

    # Note that for example apps, the ESP Registry will append the these README files to
    # the main README.md at publish time, and generate anchor text hyperlinks.
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/benchmark"                "README.md"  APPEND
    copy_wolfssl_source  "$THIS_SOURCE"  "wolfcrypt/test"                     "README.md"  APPEND

    # TODO remove
    # Files known to need attention
    # The current examples expect user_settings in the root include directory
    # this can be removed once subsequent PR updates are accepted for examples
    cp ./lib/user_settings.h ./include/user_settings.h

    # The component registry needs a newer version of esp32-crypt.h
    # cp ./lib/esp32-crypt.h   ./wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h
    # End TODO
fi
echo ""

#**************************************************************************************************
# make sure the version found in ./$THIS_COMPONENT/version.h matches  that in ./idf_component.yml
#**************************************************************************************************
if [ -e "./$THIS_COMPONENT/version.h" ]; then
    WOLFSSL_VERSION=$(grep "${COMPONENT_VERSION_STRING}" ./"${THIS_COMPONENT}"/version.h | awk '{print $3}' | tr -d '"')
    grep "$WOLFSSL_VERSION" ./idf_component.yml
    THIS_ERROR_CODE=$?
    if [ $THIS_ERROR_CODE -ne 0 ]; then
        echo ""
        echo "Version text in idf_component.yml does not match ./$THIS_COMPONENT/version.h ($WOLFSSL_VERSION). Please edit and try again."
        # optionally exit TODO?

        # exit 1
    else
        echo ""
        echo "Confirmed idf_component.yml matches ./$THIS_COMPONENT/version.h the version text: $WOLFSSL_VERSION"
        echo ""
    fi
else
    echo "ERROR: ./$THIS_COMPONENT/version.h not found"
    exit 1
fi

#**************************************************************************************************
# All files from the wolfssl/IDE/Espressif/ESP-IDF/examples
# will be copied to the local ESP Registry ./examples/ directory
#
# Define the source directory and destination directory.
# We start in           IDE/Espressif/component-manager
# We want examples from IDE/Espressif/ESP-IDF/examples
#
# We'll copy examples to publish into our local examples
# We start in           IDE/Espressif/component-manager
# Copy example files to IDE/Espressif/component-manager/examples
destination_dir="examples"

# Check if the destination directory exists, and create it if it doesn't
if [ ! -d "$destination_dir" ]; then
    mkdir -p "$destination_dir"
else
    rm -rf ../component-manager/examples
    mkdir -p "$destination_dir"
fi

# Check that we have a manifest for examples.
if [ -f "component_manifest.txt" ]; then
    echo "Using manifest file: component_manifest.txt"
else
    echo "Error: component_manifest.txt not found and is needed for examples."
    exit 1
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
        full_source_path="$EXAMPLE_SOURCE_DIR/$file_path"
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
    fi # comment or file check
done < "component_manifest.txt" # loop through each of the lines in component_manifest.txt
echo ""

#**************************************************************************************************
# Each project will be initialized with idf_component.yml in the project directory.
#**************************************************************************************************
echo "------------------------------------------------------------------------"
echo "Initialize projects with idf_component.yml"
echo "------------------------------------------------------------------------"
if [ "$IDF_COMPONENT_REGISTRY_URL" == "$PRODUCTION_URL" ]; then
    export IDF_EXAMPLE_SOURCE="./lib/idf_component.yml"
else
    if [ "$IDF_COMPONENT_REGISTRY_URL" == "$STAGING_URL" ]; then
        export IDF_EXAMPLE_SOURCE="./lib/idf_component-staging-$USER.yml"
    else
        echo ""
        echo "WARNING: unexpected IDF_COMPONENT_REGISTRY_URL value = $IDF_COMPONENT_REGISTRY_URL"
        echo "Expected blank or $STAGING_URL or $PRODUCTION_URL"
        exit 1
    fi
fi
echo ""

#**************************************************************************************************
# make sure the idf_component.yml (or idf_component-staging-[user name].yml) file exists
#**************************************************************************************************
if [ -f "$IDF_EXAMPLE_SOURCE" ]; then
    echo "Examples will use: $IDF_EXAMPLE_SOURCE"
else
    echo "Error: staging environment found, but required example component yml file does not exist: $IDF_EXAMPLE_SOURCE"
    exit 1
fi

#**************************************************************************************************
# each example needs a idf_component.yml from  ./lib copied into [example]/name/
#**************************************************************************************************
find ./examples/ -maxdepth 1 -mindepth 1 -type d -print0 | xargs -0 -I {} sh -c "echo 'Copying $IDF_EXAMPLE_SOURCE to {}/main/idf_component.yml ' && cp $IDF_EXAMPLE_SOURCE {}/main/idf_component.yml" || exit 1

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
        echo "Continuing with missing files..."
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
# end of prep

#**************************************************************************************************
# Build all the projects in ./examples/
# if an error is encountered, create a semaphore file called build_failed.txt
#
# NOTE: this checks if the *current* examples build with the *CURRENT* (already published) ESP Registry version.
# Run this script a second time (don't publish) to ensure the examples build with freshly-published wolfSSL code.
# Reminder that there may be a delay of several minutes or more between the time of publish, and the time
# when the files are actually available.

# This build is for the *prior* version of ESP Component (the one *already* published)
# find  ./examples/ -maxdepth 1 -mindepth 1 -type d | xargs -I {} sh -c 'cd {} && echo "\n\nBuilding {} for minimum component version: " && grep "wolfssl/wolfssl:" main/idf_component.yml && echo "\n\n" && idf.py build || touch ../../build_failed.txt'

# we'll do a test build of the current to-be-published version of wolfSSL
#
# get a list of all directory names ---------------------| (SC2038 Use -print0/-0 or -exec + to allow for non-alphanumeric filenames.)
# send to xargs -----------------------------------------|-----------|
# use each directory name found as a parameter "{}" -----|-----------|-|
# run each as a shell script command --------------------|-----------|----|
# print a progress message for each example being built -|-----------|------------|
# send each directory found as a parameter to wolfssl_build_example.sh to build the project -------------------------------------------|
# The build_failed.txt will exist when one or more of the builds has failed -----------------------------------------------------------|------|
#
# TODO build disabled
#find ./examples/ -maxdepth 1 -mindepth 1 -type d -print0 | xargs -0 -I {} sh -c 'echo "\n\nBuilding {} " && ./wolfssl_build_example.sh {} || touch ../../build_failed.txt'

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
echo "Samples files to publish:"
echo ""
find ./examples/ -print
echo ""

# Check to see if we failed on this build:
if [ -e "./build_failed.txt" ]; then
    echo "Build of 1 or more examples failed!"
else
    echo "Build success for examples!"
fi

echo ""
echo "Important: Review the list of files above to confirm they should ALL be published with the component."
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
if [ -z "$IDF_COMPONENT_REGISTRY_URL" ]; then
    echo "ERROR: IDF_COMPONENT_REGISTRY_URL should have been set."
    echo ""
    exit 1
else
    echo "Publishing local $THIS_COMPONENT source to ESP Registry: $IDF_COMPONENT_REGISTRY_URL"
    echo ""
    echo "======================================================================================="
    echo "======================================================================================="
    echo ""
    echo "WARNING: The specified $THIS_COMPONENT_NAME component will be replaced upon completion."
    echo ""
    echo "======================================================================================="
    echo "======================================================================================="
    echo ""
fi

COMPONENT_MANAGER_PUBLISH=
until [ "${COMPONENT_MANAGER_PUBLISH^}" == "Y" ] || [ "${COMPONENT_MANAGER_PUBLISH^}" == "N" ]; do
    read -r -n1 -p "Proceed to publish $THIS_COMPONENT? (Y/N) " COMPONENT_MANAGER_PUBLISH
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
    # In the case of staging, the component will be called "[username]__mywolfssl"
    #

    if [ "$IDF_COMPONENT_REGISTRY_URL" == "$PRODUCTION_URL" ]; then
        # echo "WARNING: The live wolfSSL will be replaced upon completion."
        echo "DISABLED: "
        echo "compote component upload --namespace wolfssl --name $THIS_COMPONENT_NAME" || exit 1
    else
        if [ "$IDF_COMPONENT_REGISTRY_URL" == "$STAGING_URL" ]; then
            echo "Running: compote component upload --namespace $USER --name $THIS_COMPONENT_NAME"
            echo ""
            compote component upload --namespace "$THIS_NAMESPACE" --name "$THIS_COMPONENT_NAME" || exit 1
        else
            echo ""
            echo "WARNING: unexpected IDF_COMPONENT_REGISTRY_URL value = $IDF_COMPONENT_REGISTRY_URL"
            echo "Expected blank or $STAGING_URL or $PRODUCTION_URL"
            exit 1
        fi
    fi

    echo ""
    if [ -z "$IDF_COMPONENT_REGISTRY_URL" ]; then
        echo "View the new component at https://components.espressif.com/components/wolfssl/wolfssl"
    else
        echo "View the new component at $IDF_COMPONENT_REGISTRY_URL/$THIS_NAMESPACE/$THIS_COMPONENT"
    fi
    echo ""
    echo "Done!"
    echo ""
else
    echo;
    echo "No files published!"
fi
