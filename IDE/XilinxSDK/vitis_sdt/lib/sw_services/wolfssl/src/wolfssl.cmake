# Copyright (C) 2006-2026 wolfSSL Inc. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# BSP options for the wolfssl library, shown in the Vitis BSP settings
# GUI. The wolfSSL feature set itself is not set here: it comes from
# user_settings.h. See IDE/XilinxSDK/vitis_sdt/README.md.

string(CONCAT _wolfssl_desc
  "Path to the wolfSSL source checkout. Leave empty to auto-detect "
  "(works when this repository was added to Vitis from inside the "
  "checkout).")
set(wolfssl_source_path "" CACHE STRING "${_wolfssl_desc}")

string(CONCAT _wolfssl_desc
  "Absolute path to your user_settings.h. Leave empty to use "
  "user_settings.h from the domain's BSP directory (next to bsp.yaml). "
  "One of the two must exist; it configures wolfSSL for the library "
  "and every application on this domain.")
set(wolfssl_user_settings_path "" CACHE STRING "${_wolfssl_desc}")
