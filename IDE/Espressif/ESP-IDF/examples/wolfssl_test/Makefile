#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

CFLAGS += -DWOLFSSL_USER_SETTINGS

# Some of the tests are CPU intenstive, so we'll force the watchdog timer off.
# There's an espressif NO_WATCHDOG; we don't use it, as it is reset by sdkconfig.
EXTRA_CFLAGS += -DWOLFSSL_ESP_NO_WATCHDOG

PROJECT_NAME := wolfssl_test

include $(IDF_PATH)/make/project.mk
