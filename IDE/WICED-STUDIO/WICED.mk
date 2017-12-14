#
# Copyright 2018, Cypress Semiconductor Corporation or a subsidiary of 
 # Cypress Semiconductor Corporation. All Rights Reserved.
 # This software, including source code, documentation and related
 # materials ("Software"), is owned by Cypress Semiconductor Corporation
 # or one of its subsidiaries ("Cypress") and is protected by and subject to
 # worldwide patent protection (United States and foreign),
 # United States copyright laws and international treaty provisions.
 # Therefore, you may use this Software only as provided in the license
 # agreement accompanying the software package from which you
 # obtained this Software ("EULA").
 # If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 # non-transferable license to copy, modify, and compile the Software
 # source code solely for use in connection with Cypress's
 # integrated circuit products. Any reproduction, modification, translation,
 # compilation, or representation of this Software except as specified
 # above is prohibited without the express written permission of Cypress.
 #
 # Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 # EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 # WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 # reserves the right to make changes to the Software without notice. Cypress
 # does not assume any liability arising out of the application or use of the
 # Software or any product or circuit described in the Software. Cypress does
 # not authorize its products for use in any products where a malfunction or
 # failure of the Cypress product may reasonably be expected to result in
 # significant property damage, injury or death ("High Risk Product"). By
 # including Cypress's product in a High Risk Product, the manufacturer
 # of such system or application assumes all risk of such use and in doing
 # so agrees to indemnify Cypress against all liability.
#

NAME = WICED

$(NAME)_SOURCES := internal/wiced_core.c

ifndef USES_BOOTLOADER_OTA
USES_BOOTLOADER_OTA :=1
endif

ifeq ($(BUILD_TYPE),debug)
#$(NAME)_COMPONENTS += test/malloc_debug
endif

# Check if WICED level API is required
ifndef NO_WICED_API
$(NAME)_SOURCES += internal/time.c \
                   internal/system_monitor.c \
                   internal/wiced_lib.c \
                   internal/wiced_crypto.c \
                   internal/waf.c \
                   internal/wiced_audio.c

# Check if Wi-Fi is not required
ifndef NO_WIFI
$(NAME)_SOURCES += internal/wifi.c \
                   internal/wiced_wifi_deep_sleep.c \
                   internal/wiced_cooee.c \
                   internal/wiced_easy_setup.c \
                   internal/wiced_filesystem.c

$(NAME)_INCLUDES += security/BESL/crypto_internal \
                    security/BESL/include \
                    security/BESL/host/WICED \
                    security/BESL/WPS \
                    security/PostgreSQL \
                    security/PostgreSQL/include \
                    security/BESL/wolfssl_lib/wolfssl \
                    security/BESL/mbedtls_open/include

$(NAME)_COMPONENTS += WICED/WWD \
                      WICED/security/BESL \
                      WICED/security/PostgreSQL \
                      protocols/DNS

GLOBAL_DEFINES += ADD_NETX_EAPOL_SUPPORT
GLOBAL_DEFINES += NX_FRAGMENT_IMMEDIATE_ASSEMBLY

ifndef NETWORK
NETWORK := NetX_Duo
$(NAME)_COMPONENTS += NetX_Duo
endif

else #ifndef NO_WIFI
GLOBAL_INCLUDES += WWD/include \
                   security/BESL/include \
                   security/BESL/host/WICED \
                   security/BESL/crypto_internal \
                   security/PostgreSQL \
                   security/PostgreSQL/include \
                   security/BESL/wolfssl_lib/wolfssl \
                   security/BESL/mbedtls_open/include

endif #ifndef NO_WIFI

else # ifndef NO_WICED_API
ifneq ($(NETWORK),)
$(NAME)_COMPONENTS += WICED/WWD
else # NETWORK
GLOBAL_INCLUDES += WWD/include
endif # NETWORK
GLOBAL_INCLUDES += security/BESL/include \
                   security/BESL/host/WICED \
                   security/BESL/crypto_internal \
                   security/PostgreSQL/include \
                   security/BESL/wolfssl_lib/wolfssl \
                   security/BESL/mbedtls_open/include
GLOBAL_DEFINES += NO_WICED_API
endif # ifndef NO_WICED_API

$(NAME)_CHECK_HEADERS := internal/wiced_internal_api.h \
                         ../include/default_wifi_config_dct.h \
                         ../include/resource.h \
                         ../include/wiced.h \
                         ../include/wiced_defaults.h \
                         ../include/wiced_easy_setup.h \
                         ../include/wiced_framework.h \
                         ../include/wiced_management.h \
                         ../include/wiced_platform.h \
                         ../include/wiced_rtos.h \
                         ../include/wiced_tcpip.h \
                         ../include/wiced_time.h \
                         ../include/wiced_utilities.h \
                         ../include/wiced_crypto.h \
                         ../include/wiced_wifi.h \
                         ../include/wiced_wifi_deep_sleep.h

# Add WICEDFS as default if filesystem is not specified
ifdef PLATFORM_FILESYSTEM_FILEX
GLOBAL_DEFINES += USING_FILEX
$(NAME)_COMPONENTS += filesystems/FileX
else
GLOBAL_DEFINES += USING_WICEDFS
$(NAME)_COMPONENTS += filesystems/wicedfs
endif

# Add MCU component
$(NAME)_COMPONENTS += WICED/platform/MCU/$(HOST_MCU_FAMILY)

# Define the default ThreadX and FreeRTOS starting stack sizes
FreeRTOS_START_STACK := 800
ThreadX_START_STACK  := 800
NuttX_START_STACK    := 4000

GLOBAL_DEFINES += WWD_STARTUP_DELAY=10 \
                  BOOTLOADER_MAGIC_NUMBER=0x4d435242
                  APP_NAME=$$(SLASH_QUOTE)$(APP)$$(SLASH_QUOTE)

GLOBAL_INCLUDES += . \
                   platform/include

$(NAME)_CFLAGS  = $(COMPILER_SPECIFIC_PEDANTIC_CFLAGS)

$(NAME)_SOURCES += internal/wiced_low_power.c

$(NAME)_UNIT_TEST_SOURCES := internal/unit/wiced_unit.cpp
MOCKED_FUNCTIONS += malloc malloc_named
