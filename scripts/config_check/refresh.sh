#!/bin/bash

# requires  autoconf, automake and libtool
# See https://github.com/wolfSSL/wolfssl/blob/master/INSTALL

# we expect to be starting in the scripts directory, so move to the parent.
cd "../.."

# the location of wolfSSL where the ./configure script should run
WOLFSSL_REPO="$PWD"


if [ ! -f "configure" ]; then
    echo "configure not found! did you forget to run autogen.sh in $PWD?"
    exit 1
fi

echo This WOLFSSL_REPO = $PWD

# the directory where output files go (a github repo is helpful for tracking changes)
WOLFSSL_FILE_ROOT="$WOLFSSL_REPO/scripts/config_check"
echo "WOLFSSL_FILE_ROOT = $WOLFSSL_FILE_ROOT"

mkdir -p "$WOLFSSL_FILE_ROOT"

# set a variable for the input command
WOLFSSL_CMD_FILE="$WOLFSSL_FILE_ROOT/cmd.txt"

# make sure we actually have a cmd.txt file
if [ ! -f "$WOLFSSL_CMD_FILE" ]; then
    echo "Looking for $WOLFSSL_CMD_FILE"
    echo "The needed cmd.txt file was not found. Please see README.md file."
    exit 1
fi

# setup some variables for output files
WOLFSSL_OUTPUT="$WOLFSSL_FILE_ROOT/output.txt"
WOLFSSL_OPTIONS="$WOLFSSL_FILE_ROOT/options.h"
WOLFSSL_YES="$WOLFSSL_FILE_ROOT/Enabled-Features.txt"
WOLFSSL_NO="$WOLFSSL_FILE_ROOT/Disabled-Features.txt"

# we'll want to run configure from the root directory of wolfssl
cd "$WOLFSSL_REPO"

# save current help text for reference
./configure --help > "./help.txt"
retVal=$?
if [ $retVal -ne 0 ]; then
    echo "Error"
    exit $retVal
fi

# show the command text found
echo "CMD File= $WOLFSSL_CMD_FILE"
echo ""

# test drive the cat, cut, awk, sed as a preview.
# this command should exactly math the one below: WOLFSSL_CMD="$(cat ...
cat $WOLFSSL_CMD_FILE | cut -d'#' -f1 | awk NF | sed 's/\\//g'> /dev/null

# the first digit will be cat exit code, the second will be cut exit code.
# the third digit is awk result, forth is sed result.
# success is expected to be "0000".
retVal="${PIPESTATUS[0]}${PIPESTATUS[1]}${PIPESTATUS[2]}${PIPESTATUS[3]}"

# both the command and tee output must return a success (zero) to proceed.
# echo "cat & cut = $retVal"
if [ "$retVal" != "0000" ]; then
    echo "Error parsing the command in $WOLFSSL_CMD_FILE"
    exit 1
fi

# get the contents of the command file, trimming all text after the # character
# this exact command text should have been preview tested (above).
WOLFSSL_CMD="$(cat $WOLFSSL_CMD_FILE | cut -d'#' -f1 | awk NF | sed 's/\\//g')"
retVal=$?

if [ $retVal -ne 0 ]; then
    echo "Error assigning command value."
    exit $retVal
fi


echo "Running command: "         > $WOLFSSL_OUTPUT
echo ""                         >> $WOLFSSL_OUTPUT
echo "CMD = $WOLFSSL_CMD"        | tee -a "$WOLFSSL_OUTPUT"
echo ""

echo Running configure from $PWD | tee -a "$WOLFSSL_OUTPUT"

echo ""                         >> $WOLFSSL_OUTPUT
echo "------------------------" >> $WOLFSSL_OUTPUT
echo "Output:"                  >> $WOLFSSL_OUTPUT
echo "------------------------" >> $WOLFSSL_OUTPUT
echo ""                         >> $WOLFSSL_OUTPUT

# Execute the command:
# bash -c $WOLFSSL_CMD
$(echo $WOLFSSL_CMD)             | tee -a "$WOLFSSL_OUTPUT"

# the first digit will be CMD exit code; the second will be tee exit code.
# success is expected to be "00"
retVal="${PIPESTATUS[0]}${PIPESTATUS[1]}"

# check if the command failed, but tee success
if [ "$retVal" == "10" ]; then
    echo "The command in $WOLFSSL_CMD_FILE failed."
    exit 1
fi

# check if the command was successful, but tee failes
if [ "$retVal" == "01" ]; then
    echo "Error running command to tee in $WOLFSSL_CMD_FILE"
    exit 1
fi

# both the command and tee output must return a success (zero) to proceed.
if [ "$retVal" != "00" ]; then
    echo "Error running command $WOLFSSL_CMD_FILE"
    exit 1
fi

# save the generated options.h
echo ""
echo Copying $PWD/wolfssl/options.h to "$WOLFSSL_OPTIONS"
cp wolfssl/options.h "$WOLFSSL_OPTIONS"

# pull out the enabled and disabled features into separate files
echo ""
echo "Saving enabled summary to $WOLFSSL_YES"
grep  "\*" "$WOLFSSL_OUTPUT" | grep yes > "$WOLFSSL_YES"

echo ""
echo "Saving disabled summary to $WOLFSSL_NO"
grep  "\*" "$WOLFSSL_OUTPUT" | grep no > "$WOLFSSL_NO"

echo ""
echo "See output history in $WOLFSSL_OUTPUT"

echo ""
echo "Done! Thank you for using wolfSSL"
echo ""
