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

NAME := Supplicant_BESL

ifeq ($(WICED_SECURITY),ROM)
BESL_LIB_TYPE              := rom
else
BESL_LIB_TYPE              := generic
endif

ifneq ($(wildcard $(CURDIR)BESL_$(BESL_LIB_TYPE).$(HOST_ARCH)$(DOT_TOOLCHAIN_TYPE).release.a),)
ifeq ($(HOST_HARDWARE_CRYPTO),1)
# Micro specific prebuilt library with hardware crypto support
$(NAME)_PREBUILT_LIBRARY := BESL_$(BESL_LIB_TYPE).$(HOST_OPENOCD)$(DOT_TOOLCHAIN_TYPE).release.a
else
# Architecture specific prebuilt library
$(NAME)_PREBUILT_LIBRARY := BESL_$(BESL_LIB_TYPE).$(HOST_ARCH)$(DOT_TOOLCHAIN_TYPE).release.a
endif # ifeq ($(HOST_HARDWARE_CRYPTO),1)
else
# Build from source (Broadcom internal)
include $(CURDIR)BESL_src.mk
endif # ifneq ($(wildcard $(CURDIR)ThreadX.$(HOST_ARCH).release.a),)


$(NAME)_SOURCES += host/WICED/besl_host.c \
                   host/WICED/wiced_tls.c \
                   host/WICED/wiced_wps.c \
                   host/WICED/wiced_p2p.c \
                   host/WICED/cipher_suites.c \
                   host/WICED/tls_cipher_suites.c \
                   host/WICED/dtls_cipher_suites.c \
                   host/WICED/p2p_internal.c \
                   host/WICED/wiced_supplicant.c \
                   P2P/p2p_events.c \
                   P2P/p2p_frame_writer.c \
                   host/WICED/wiced_dtls.c

GLOBAL_INCLUDES := host/WICED \
                   TLS \
                   crypto_internal \
                   WPS \
                   include \
                   P2P \
                   crypto_internal/homekit_srp \
                   crypto_internal/ed25519 \
                   supplicant \
                   DTLS \
                   wolfssl_lib/wolfssl \
                   mbedtls_open/include

GLOBAL_DEFINES  := ADD_LWIP_EAPOL_SUPPORT  NXD_EXTENDED_BSD_SOCKET_SUPPORT OPENSSL STDC_HEADERS

$(NAME)_COMPONENTS += utilities/base64
$(NAME)_COMPONENTS += utilities/TLV
$(NAME)_COMPONENTS += utilities/linked_list

$(NAME)_COMPONENTS += BESL/mbedtls_open
$(NAME)_COMPONENTS += BESL/wolfssl_lib

ifeq ($(IAR),)
$(NAME)_CFLAGS =  -fno-strict-aliasing
endif
