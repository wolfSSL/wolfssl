#!/bin/bash

# check if IDF_PATH is set
if [ -z "$IDF_PATH" ]; then
    # no IDP PATH found, perhaps set an explicit file in parameters
    if [ "$1" == "" ]; then
      # no IDDF_PATH and no parameter: nothing to do
      echo "Please follows the instruction of ESP-IDF installation and set IDF_PATH."
      echo " or "
      echo "Please specify a version.h file to append git information."
      exit 1
    fi

    # NO IDF path, but a non-blank parameter, does the parameter file exist?
    if [ -f "$1" ]; then
      echo "Adding git version info to file: $1"
      WOLFSSL_VERSION_FILE="$1"
    else
      echo "File not found: $1"
      exit 1
    fi
else
    # we have an ESP-IDF path, but was thre a parameter to override?
    if [ "$1" == "" ]; then
        WOLFSSL_VERSION_FILE="$IDF_PATH"/components/wolfssl/wolfssl/version.h
    else
        WOLFSSL_VERSION_FILE="$1"
    fi
    # there's $IDF_PATH value, is wolfSSL installed?
fi

# check to ensure the file to update exists
if [ -f "$WOLFSSL_VERSION_FILE" ]; then
  echo "Adding git version info to file: $WOLFSSL_VERSION_FILE"
else
  echo "File not found: $WOLFSSL_VERSION_FILE"
  exit 1
fi



# assemble a string of data to pass to awk that will contain the new git hash version info
# we plan to add lines like these:
#
#undef  LIBWOLFSSL_VERSION_GIT_HASH
#define LIBWOLFSSL_VERSION_GIT_HASH "adb406e1eebf05e452afca98fa9bf3ccd7abcfca"
#undef  LIBWOLFSSL_VERSION_GIT_SHORT_HASH
#define LIBWOLFSSL_VERSION_GIT_SHORT_HASH "adb406e1e"
#undef  LIBWOLFSSL_VERSION_GIT_HASH_DATE
#define LIBWOLFSSL_VERSION_GIT_HASH_DATE "Sat Jan 5 09:00:00 2013 +0100"
#
NEW_VERSION_LINES="{ print;                                                                                     \
                     print \"#undef  LIBWOLFSSL_VERSION_GIT_HASH\";                                             \
                     print \"#define LIBWOLFSSL_VERSION_GIT_HASH \x22$(git rev-parse HEAD)\x22\";               \
                     print \"#undef  LIBWOLFSSL_VERSION_GIT_SHORT_HASH\";                                       \
                     print \"#define LIBWOLFSSL_VERSION_GIT_SHORT_HASH \x22$(git rev-parse --short HEAD)\x22\"; \
                     print \"#undef  LIBWOLFSSL_VERSION_GIT_HASH_DATE\";                                        \
                     print \"#define LIBWOLFSSL_VERSION_GIT_HASH_DATE \x22$(git show --no-patch --no-notes --pretty='%cd'  $(git rev-parse HEAD))\x22\"; \
                     next }1"

# save interim results in temp file that we create:
NEW_VERSION_FILE="$WOLFSSL_VERSION_FILE".tmp
cat "$WOLFSSL_VERSION_FILE" > "$NEW_VERSION_FILE"

# remove any prior git hash defines
sed -i.bak '/LIBWOLFSSL_VERSION_GIT_HASH/d'       "$NEW_VERSION_FILE"
retVal=$?
if [ $retVal -ne 0 ]; then
    echo "Error during SED line deletion #1"
    exit $retVal
fi

sed -i.bak '/LIBWOLFSSL_VERSION_GIT_SHORT_HASH/d' "$NEW_VERSION_FILE"
retVal=$?
if [ $retVal -ne 0 ]; then
    echo "Error during SED line deletion #2"
    exit $retVal
fi

sed -i.bak '/LIBWOLFSSL_VERSION_GIT_HASH_DATE/d' "$NEW_VERSION_FILE"
retVal=$?
if [ $retVal -ne 0 ]; then
    echo "Error during SED line deletion #3"
    exit $retVal
fi


# append the git hash values after the LIBWOLFSSL_VERSION_HEX
# awk "/LIBWOLFSSL_VERSION_HEX/ $NEW_VERSION_LINES" "$NEW_VERSION_FILE" >  $WOLFSSL_VERSION_FILE"
# awk "/LIBWOLFSSL_VERSION_HEX/ $NEW_VERSION_LINES" "$NEW_VERSION_FILE"

awk "/LIBWOLFSSL_VERSION_HEX/ $NEW_VERSION_LINES" "$NEW_VERSION_FILE" > "$WOLFSSL_VERSION_FILE"
retVal=$?
if [ $retVal -ne 0 ]; then
    echo "Error during awk replacement."
    exit $retVal
fi

# cleanup
if [ -f "$NEW_VERSION_FILE" ]; then
  rm "$NEW_VERSION_FILE"
fi

if [ -f "$NEW_VERSION_FILE".bak ]; then
  rm "$NEW_VERSION_FILE".bak
fi

echo "Update complete."
