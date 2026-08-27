# Copyright (C) 2006-2026 wolfSSL Inc. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Builds the wolfssl library for the Vitis Unified IDE (SDT flow). The
# sources compile in place from the checkout; nothing is copied or
# listed by hand. See IDE/XilinxSDK/vitis_sdt/README.md.

cmake_minimum_required(VERSION 3.15)
project(wolfssl)

find_package(common)

include(${CMAKE_CURRENT_SOURCE_DIR}/wolfssl.cmake NO_POLICY_SCOPE)

# Find the wolfSSL checkout: the wolfssl_source_path option, then the
# path recorded in lib_list.yaml, then walking up from this directory,
# then WOLFSSL_ROOT. Fix Windows backslashes first: Vitis passes the
# path options with backslashes, which CMake reads as escapes like \f.
if(wolfssl_source_path)
  file(TO_CMAKE_PATH "${wolfssl_source_path}" wolfssl_source_path)
endif()
if(wolfssl_user_settings_path)
  file(TO_CMAKE_PATH "${wolfssl_user_settings_path}" wolfssl_user_settings_path)
endif()
if(wolfssl_source_path AND EXISTS ${wolfssl_source_path}/wolfcrypt/src)
  set(WOLFSSL_REPO_ROOT ${wolfssl_source_path})
endif()
if(NOT DEFINED WOLFSSL_REPO_ROOT AND EXISTS ${CMAKE_SOURCE_DIR}/lib_list.yaml)
  file(READ ${CMAKE_SOURCE_DIR}/lib_list.yaml _wolfssl_lib_list)
  string(REGEX MATCH "wolfssl:.*" _wolfssl_lib_entry "${_wolfssl_lib_list}")
  string(REGEX MATCH "path:[ \t\r\n]+-[ \t]+([^\r\n]+)"
    _wolfssl_path_match "${_wolfssl_lib_entry}")
  if(CMAKE_MATCH_1)
    file(TO_CMAKE_PATH "${CMAKE_MATCH_1}" _wolfssl_pkg_path)
    # The package sits at IDE/XilinxSDK/vitis_sdt/lib/sw_services/wolfssl
    get_filename_component(_wolfssl_candidate
      "${_wolfssl_pkg_path}/../../../../../.." ABSOLUTE)
    if(EXISTS ${_wolfssl_candidate}/wolfcrypt/src)
      set(WOLFSSL_REPO_ROOT ${_wolfssl_candidate})
    endif()
  endif()
endif()
if(NOT DEFINED WOLFSSL_REPO_ROOT)
  get_filename_component(_wolfssl_candidate
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../.. ABSOLUTE)
  if(EXISTS ${_wolfssl_candidate}/wolfcrypt/src)
    set(WOLFSSL_REPO_ROOT ${_wolfssl_candidate})
  elseif(DEFINED ENV{WOLFSSL_ROOT} AND EXISTS $ENV{WOLFSSL_ROOT}/wolfcrypt/src)
    file(TO_CMAKE_PATH "$ENV{WOLFSSL_ROOT}" WOLFSSL_REPO_ROOT)
  endif()
endif()
# A user_settings.h is required; the default spot is the domain's BSP
# directory (next to bsp.yaml), and wolfssl_user_settings_path overrides
# it. A missing file must not fail configure (that would undo adding the
# library), so instead a stub fails the compile with instructions.
set(_wolfssl_user_settings "")
if(wolfssl_user_settings_path)
  set(_wolfssl_user_settings ${wolfssl_user_settings_path})
elseif(EXISTS ${CMAKE_SOURCE_DIR}/user_settings.h)
  set(_wolfssl_user_settings ${CMAKE_SOURCE_DIR}/user_settings.h)
elseif(EXISTS ${CMAKE_SOURCE_DIR}/bsp.yaml)
  # First build with no settings anywhere: create a starter file for
  # the user to edit. Made once, never overwritten. The bsp.yaml check
  # makes sure this only happens inside a real BSP.
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/user_settings_template.h
    ${CMAKE_SOURCE_DIR}/user_settings.h COPYONLY)
  message(STATUS
    "wolfssl: created starter user_settings.h in the BSP directory; "
    "edit it for your project and rebuild the platform")
  set(_wolfssl_user_settings ${CMAKE_SOURCE_DIR}/user_settings.h)
endif()

set(_wolfssl_setup_error "")
if(NOT DEFINED WOLFSSL_REPO_ROOT)
  string(CONCAT _wolfssl_setup_error
    "wolfssl: checkout not located. Set the wolfssl_source_path BSP "
    "option to the wolfSSL repository path and regenerate the BSP.")
elseif(NOT _wolfssl_user_settings)
  string(CONCAT _wolfssl_setup_error
    "wolfssl: user_settings.h required. Place your configuration file "
    "at <domain>/bsp/user_settings.h (next to bsp.yaml), or set the "
    "wolfssl_user_settings_path BSP option to its absolute path, then "
    "regenerate the BSP.")
elseif(NOT EXISTS ${_wolfssl_user_settings})
  string(CONCAT _wolfssl_setup_error
    "wolfssl: user_settings.h not found at ${_wolfssl_user_settings}. "
    "Fix the wolfssl_user_settings_path BSP option and regenerate the "
    "BSP.")
endif()
if(_wolfssl_setup_error)
  message(WARNING "${_wolfssl_setup_error}")
  set(_wolfssl_stub_src ${CMAKE_BINARY_DIR}/wolfssl_setup_error.c)
  file(WRITE ${_wolfssl_stub_src}
    "#error \"${_wolfssl_setup_error}\"\n")
  add_library(wolfssl STATIC ${_wolfssl_stub_src})
  set_target_properties(wolfssl PROPERTIES LINKER_LANGUAGE C)
  return()
endif()
message(STATUS "wolfSSL sources: ${WOLFSSL_REPO_ROOT}")
message(STATUS "wolfSSL user_settings: ${_wolfssl_user_settings}")
configure_file(${_wolfssl_user_settings}
  ${CMAKE_BINARY_DIR}/include/user_settings.h COPYONLY)

# Most wolfSSL C files compile to nothing when their feature is off, so
# the source lists below are simple. Assembly files cannot do that, so
# run the preprocessor on user_settings.h to learn which macros are on.
set(_wolfssl_probe_src ${CMAKE_BINARY_DIR}/wolfssl_config_probe.c)
file(WRITE ${_wolfssl_probe_src}
  "#include \"user_settings.h\"\n"
  "#ifdef WOLFSSL_ARMASM\n\"@CFG_ARMASM@\"\n#endif\n"
  "#ifdef WOLFSSL_ARMASM_INLINE\n\"@CFG_ARMASM_INLINE@\"\n#endif\n"
  "#ifdef HAVE_POLY1305\n\"@CFG_POLY1305@\"\n#endif\n"
  "#ifdef HAVE_CHACHA\n\"@CFG_CHACHA@\"\n#endif\n")
# Give the probe the same includes and defines as the library target below.
# A user_settings.h that pulls in BSP headers has to preprocess here too.
set(_wolfssl_probe_inc)
foreach(_wolfssl_dir
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_INCLUDE_PATH}
    ${WOLFSSL_REPO_ROOT})
  list(APPEND _wolfssl_probe_inc -I${_wolfssl_dir})
endforeach()
execute_process(
  COMMAND ${CMAKE_C_COMPILER} -E -P
    -DWOLFSSL_USER_SETTINGS
    ${_wolfssl_probe_inc}
    ${_wolfssl_probe_src}
  OUTPUT_VARIABLE _wolfssl_probe
  RESULT_VARIABLE _wolfssl_probe_rc
  ERROR_VARIABLE _wolfssl_probe_err)
if(NOT _wolfssl_probe_rc EQUAL 0)
  message(FATAL_ERROR
    "Could not preprocess the selected user_settings.h. Check the file "
    "named by wolfssl_user_settings_path. Compiler output:\n"
    "${_wolfssl_probe_err}")
endif()
foreach(_wolfssl_flag ARMASM ARMASM_INLINE POLY1305 CHACHA)
  string(FIND "${_wolfssl_probe}" "@CFG_${_wolfssl_flag}@" _wolfssl_pos)
  if(_wolfssl_pos EQUAL -1)
    set(_wolfssl_cfg_${_wolfssl_flag} FALSE)
  else()
    set(_wolfssl_cfg_${_wolfssl_flag} TRUE)
  endif()
endforeach()

# wolfCrypt: build everything except files meant to be #include'd.
file(GLOB WOLFCRYPT_SOURCES ${WOLFSSL_REPO_ROOT}/wolfcrypt/src/*.c)
list(REMOVE_ITEM WOLFCRYPT_SOURCES
  ${WOLFSSL_REPO_ROOT}/wolfcrypt/src/misc.c
  ${WOLFSSL_REPO_ROOT}/wolfcrypt/src/evp.c)
set(_sources ${WOLFCRYPT_SOURCES})

# TLS layer. Only these files build on their own; the rest of src/ is
# pulled in by ssl.c. With WOLFCRYPT_ONLY they compile to nothing.
foreach(_tls_file ssl.c internal.c tls.c tls13.c keys.c wolfio.c crl.c
    ocsp.c dtls.c dtls13.c quic.c)
  if(EXISTS ${WOLFSSL_REPO_ROOT}/src/${_tls_file})
    list(APPEND _sources ${WOLFSSL_REPO_ROOT}/src/${_tls_file})
  endif()
endforeach()

# wolfCrypt self-test and benchmark. Define NO_CRYPT_TEST or
# NO_CRYPT_BENCHMARK in user_settings.h to leave them out.
list(APPEND _sources
  ${WOLFSSL_REPO_ROOT}/wolfcrypt/test/test.c
  ${WOLFSSL_REPO_ROOT}/wolfcrypt/benchmark/benchmark.c)

# Versal Gen 2 ASU hardware offload. The port files compile to nothing
# unless user_settings.h defines WOLFSSL_VERSAL_GEN2_ASU.
file(GLOB WOLFSSL_ASU_SOURCES
  ${WOLFSSL_REPO_ROOT}/wolfcrypt/src/port/xilinx/versal_gen2_asu/*.c)
list(APPEND _sources ${WOLFSSL_ASU_SOURCES})

# ARM assembly: built when the settings define WOLFSSL_ARMASM and the
# CPU is AArch64. With WOLFSSL_ARMASM_INLINE the armv8-*_c.c files hold
# the assembly as inline C; without it the .S files are used instead.
set(_wolfssl_arm_dir ${WOLFSSL_REPO_ROOT}/wolfcrypt/src/port/arm)
set(_wolfssl_build_armasm_a64 FALSE)
if(_wolfssl_cfg_ARMASM)
  if("${CMAKE_SYSTEM_PROCESSOR}" MATCHES
      "cortexa78|cortexa72|cortexa53|aarch64")
    set(_wolfssl_build_armasm_a64 TRUE)
  else()
    message(WARNING
      "user_settings.h defines WOLFSSL_ARMASM but no assembly support is "
      "wired for ${CMAKE_SYSTEM_PROCESSOR}; expect link errors. Remove "
      "WOLFSSL_ARMASM from the settings for this domain.")
  endif()
endif()
if(_wolfssl_build_armasm_a64)
  file(GLOB WOLFSSL_ARMASM_SOURCES ${_wolfssl_arm_dir}/armv8-*.c)
  file(GLOB _wolfssl_armasm_32 ${_wolfssl_arm_dir}/armv8-32-*.c)
  if(_wolfssl_armasm_32)
    list(REMOVE_ITEM WOLFSSL_ARMASM_SOURCES ${_wolfssl_armasm_32})
  endif()
  # Without inline mode the armv8-*_c.c files carry no assembly, so drop
  # them and build the matching .S files instead.
  if(NOT _wolfssl_cfg_ARMASM_INLINE)
    file(GLOB _wolfssl_armasm_inline_c ${_wolfssl_arm_dir}/armv8-*_c.c)
    if(_wolfssl_armasm_inline_c)
      list(REMOVE_ITEM WOLFSSL_ARMASM_SOURCES ${_wolfssl_armasm_inline_c})
    endif()
    enable_language(ASM)
    file(GLOB _wolfssl_armasm_s ${_wolfssl_arm_dir}/armv8-*.S)
    file(GLOB _wolfssl_armasm_s32 ${_wolfssl_arm_dir}/armv8-32-*.S)
    if(_wolfssl_armasm_s32)
      list(REMOVE_ITEM _wolfssl_armasm_s ${_wolfssl_armasm_s32})
    endif()
    list(APPEND WOLFSSL_ARMASM_SOURCES ${_wolfssl_armasm_s})
  endif()

  # ChaCha and Poly1305 assembly assume their algorithm is on; drop
  # them when the settings leave it off.
  if(NOT _wolfssl_cfg_POLY1305)
    file(GLOB _wolfssl_armasm_poly
      ${_wolfssl_arm_dir}/armv8-poly1305*.c
      ${_wolfssl_arm_dir}/armv8-poly1305*.S)
    if(_wolfssl_armasm_poly)
      list(REMOVE_ITEM WOLFSSL_ARMASM_SOURCES ${_wolfssl_armasm_poly})
    endif()
  endif()
  if(NOT _wolfssl_cfg_CHACHA)
    file(GLOB _wolfssl_armasm_chacha
      ${_wolfssl_arm_dir}/armv8-chacha*.c
      ${_wolfssl_arm_dir}/armv8-chacha*.S)
    if(_wolfssl_armasm_chacha)
      list(REMOVE_ITEM WOLFSSL_ARMASM_SOURCES ${_wolfssl_armasm_chacha})
    endif()
  endif()
  list(APPEND _sources ${WOLFSSL_ARMASM_SOURCES})
endif()

# Publish headers to the BSP include dir. The published settings.h is
# patched to always pick user_settings.h, because the BSP flow cannot
# add compile flags to applications. The checkout is never modified.
if(NOT ${YOCTO})
  file(COPY ${WOLFSSL_REPO_ROOT}/wolfssl DESTINATION ${CMAKE_INCLUDE_PATH}/)
  file(COPY ${CMAKE_BINARY_DIR}/include/user_settings.h
    DESTINATION ${CMAKE_INCLUDE_PATH}/)
  file(COPY ${WOLFSSL_REPO_ROOT}/wolfcrypt/test/test.h
    DESTINATION ${CMAKE_INCLUDE_PATH}/wolfcrypt/test/)
  file(COPY ${WOLFSSL_REPO_ROOT}/wolfcrypt/benchmark/benchmark.h
    DESTINATION ${CMAKE_INCLUDE_PATH}/wolfcrypt/benchmark/)

  set(_published_settings ${CMAKE_INCLUDE_PATH}/wolfssl/wolfcrypt/settings.h)
  file(READ ${_published_settings} _settings_content)
  string(FIND "${_settings_content}" "Vitis SDT BSP flow" _already_patched)
  if(_already_patched EQUAL -1)
    string(CONCAT _settings_patch
      "/* Published for the Vitis SDT BSP flow: "
      "user_settings.h is always used. */\n"
      "#ifndef WOLFSSL_USER_SETTINGS\n"
      "#define WOLFSSL_USER_SETTINGS\n"
      "#endif\n")
    file(WRITE ${_published_settings}
      "${_settings_patch}${_settings_content}")
  endif()
endif()

add_library(wolfssl STATIC ${_sources})

target_compile_definitions(wolfssl PRIVATE WOLFSSL_USER_SETTINGS)

if(_wolfssl_build_armasm_a64)
  # Crypto extensions for the AArch64 assembly; placed after the
  # toolchain flags so this -mcpu wins.
  target_compile_options(wolfssl PRIVATE -mcpu=generic+crypto -mstrict-align)
endif()

# The patched header tree must shadow the checkout's own headers; the
# checkout root stays for TLS relative includes like "src/bio.c".
target_include_directories(wolfssl PRIVATE
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_INCLUDE_PATH}
  ${WOLFSSL_REPO_ROOT})

set_target_properties(wolfssl PROPERTIES LINKER_LANGUAGE C)
set_target_properties(wolfssl PROPERTIES
  ADDITIONAL_CLEAN_FILES "${CMAKE_LIBRARY_PATH}/libwolfssl.a")

# The BSP install step copies the archive into the BSP lib directory,
# where the platform export and the application linker find it.
install(TARGETS wolfssl LIBRARY DESTINATION ${CMAKE_LIBRARY_PATH}
  ARCHIVE DESTINATION ${CMAKE_LIBRARY_PATH})
