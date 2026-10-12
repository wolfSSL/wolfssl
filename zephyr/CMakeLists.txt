if(CONFIG_WOLFSSL)
  zephyr_interface_library_named(wolfSSL)

  if(CONFIG_WOLFSSL_BUILTIN)
    if(CONFIG_WOLFSSL_SETTINGS_FILE)
      target_compile_definitions(wolfSSL INTERFACE
        WOLFSSL_SETTINGS_FILE="${CONFIG_WOLFSSL_SETTINGS_FILE}"
      )
      zephyr_include_directories(
        ${APPLICATION_CONFIG_DIR}
        ${APPLICATION_CONFIG_DIR}/src
      )
    endif()

    zephyr_include_directories(
        ${ZEPHYR_CURRENT_MODULE_DIR}
        ${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl
        ${ZEPHYR_CURRENT_MODULE_DIR}/zephyr
        )

    zephyr_library()
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/zephyr/zephyr_init.c)

    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/crl.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/dtls.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/dtls13.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/internal.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/keys.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/ocsp.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/sniffer.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/ssl.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/tls.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/tls13.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/wolfio.c)

    set(WOLF_SRC ${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src)
    set(WOLF_ARM_ASM_DIR ${WOLF_SRC}/port/arm)
    if(CONFIG_WOLFCRYPT_ASM AND CONFIG_WOLFCRYPT_ARM_SYMMETRIC_ASM)
      if(CONFIG_CPU_CORTEX_M)
        set(WOLF_ARM_ASM_PREFIX thumb2)
      elseif(CONFIG_ARM64)
        set(WOLF_ARM_ASM_PREFIX armv8)
      else()
        set(WOLF_ARM_ASM_PREFIX armv8-32)
      endif()
    endif()

    # FIPS Boundary
    if(CONFIG_WOLFCRYPT_FIPS_V7 OR CONFIG_WOLFCRYPT_FIPS_READY)
      # src/include.am BUILD_FIPS_V7_PLUS order; files a build does not select compile empty.
      set(WOLF_BOUNDARY hmac random kdf rsa ecc aes sha sha256 sha512 sha3 dh cmac
          curve448 ed448 curve25519 ed25519 pwdbased sp_c32 sp_c64 sp_x86_64
          sp_arm32 sp_armthumb sp_arm64 sp_cortexm wc_mlkem wc_mlkem_poly
          wc_mldsa wc_lms wc_lms_impl wc_xmss wc_xmss_impl wc_slhdsa)
      set(WOLF_BOUNDARY_ASM ON)
    else()
      set(WOLF_BOUNDARY hmac random kdf rsa ecc aes sha sha256 sha512 sha3 dh cmac)
      set(WOLF_BOUNDARY_ASM OFF)
    endif()
    # The v7 boundary carries each algorithm's assembly right after it.
    set(WOLF_ARM_ASM_aes aes-asm_c)
    set(WOLF_ARM_ASM_sha256 sha256-asm_c)
    set(WOLF_ARM_ASM_sha512 sha512-asm_c)
    set(WOLF_ARM_ASM_sha3 sha3-asm_c)
    set(WOLF_ARM_ASM_ed25519 curve25519_c)
    set(WOLF_ARM_ASM_wc_mlkem_poly mlkem-asm_c)
    set(WOLF_X86_ASM_sha256 sha256_asm)
    set(WOLF_X86_ASM_sha512 sha512_asm)
    set(WOLF_X86_ASM_sha3 sha3_asm)
    set(WOLF_X86_ASM_ed25519 fe_x25519_asm)
    set(WOLF_X86_ASM_wc_mlkem_poly wc_mlkem_asm)
    set(WOLF_X86_ASM_wc_mldsa wc_mldsa_asm)

    if(CONFIG_WOLFCRYPT_FIPS)
      set(WOLF_FIPS_SRCS ${WOLF_SRC}/wolfcrypt_first.c)
    endif()
    foreach(f ${WOLF_BOUNDARY})
      list(APPEND WOLF_FIPS_SRCS ${WOLF_SRC}/${f}.c)
      if(WOLF_BOUNDARY_ASM AND WOLF_ARM_ASM_PREFIX AND WOLF_ARM_ASM_${f})
        list(APPEND WOLF_FIPS_SRCS ${WOLF_ARM_ASM_DIR}/${WOLF_ARM_ASM_PREFIX}-${WOLF_ARM_ASM_${f}}.c)
      elseif(WOLF_BOUNDARY_ASM AND CONFIG_WOLFCRYPT_ASM AND CONFIG_X86_64 AND WOLF_X86_ASM_${f})
        list(APPEND WOLF_FIPS_SRCS ${WOLF_SRC}/${WOLF_X86_ASM_${f}}.S)
      endif()
    endforeach()
    if(CONFIG_WOLFCRYPT_FIPS)
      list(APPEND WOLF_FIPS_SRCS ${WOLF_SRC}/fips.c ${WOLF_SRC}/fips_test.c
           ${WOLF_SRC}/wolfcrypt_last.c)
    endif()
    zephyr_library_sources(${WOLF_FIPS_SRCS})

    # The integrity test hashes the boundary .text and .rodata as two ranges, so
    # keep each in one piece and in file order: no sorting, splitting or merging.
    if(WOLF_BOUNDARY_ASM AND CONFIG_WOLFCRYPT_FIPS)
      if(CONFIG_LINKER_SORT_BY_ALIGNMENT)
        message(FATAL_ERROR "wolfCrypt FIPS needs CONFIG_LINKER_SORT_BY_ALIGNMENT=n: "
                "sorting by alignment moves boundary code out of the hashed range")
      endif()
      set_source_files_properties(${WOLF_FIPS_SRCS} PROPERTIES COMPILE_OPTIONS
          "-fno-function-sections;-fno-data-sections;-fno-merge-constants")
    endif()
    # native_sim links like a host program and keeps file order without this.
    if(WOLF_BOUNDARY_ASM AND CONFIG_WOLFCRYPT_FIPS AND NOT CONFIG_ARCH_POSIX)
      set(WOLF_FIPS_LD ${CMAKE_CURRENT_BINARY_DIR}/wolfcrypt_fips_rodata.ld)
      file(WRITE ${WOLF_FIPS_LD} "SECTION_PROLOGUE(wolfcrypt_fips_rodata,,)\n{\n")
      foreach(s ${WOLF_FIPS_SRCS})
        get_filename_component(n ${s} NAME)
        file(APPEND ${WOLF_FIPS_LD}
            "    *lib${ZEPHYR_CURRENT_LIBRARY}.a:${n}.obj(.rodata .rodata.*)\n")
      endforeach()
      file(APPEND ${WOLF_FIPS_LD} "} GROUP_ROM_LINK_IN(RAMABLE_REGION, ROMABLE_REGION)\n")
      zephyr_linker_sources(ROM_SECTIONS ${WOLF_FIPS_LD})
    endif()

    # Sources the v7 boundary owns, added here only when outside it.
    foreach(f curve25519 curve448 ed25519 ed448 pwdbased sp_arm32 sp_arm64
              sp_armthumb sp_c32 sp_c64 sp_cortexm sp_x86_64 wc_lms wc_lms_impl
              wc_mldsa wc_mlkem wc_mlkem_poly wc_slhdsa wc_xmss wc_xmss_impl)
      if(NOT f IN_LIST WOLF_BOUNDARY)
        zephyr_library_sources(${WOLF_SRC}/${f}.c)
      endif()
    endforeach()

    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/arc4.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/argon2.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/ascon.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/asm.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/asn.c)
    #zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/async.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/blake2b.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/blake2s.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/camellia.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/chacha.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/chacha20_poly1305.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/coding.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/compress.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/cpuid.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/cryptocb.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/des3.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/dsa.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/ecc_fp.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/eccsi.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/error.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/falcon.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/fe_448.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/fe_low_mem.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/fe_operations.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/ge_448.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/ge_low_mem.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/ge_operations.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/hash.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/integer.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/logging.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/md2.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/md4.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/md5.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/memory.c)
    #zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/misc.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/pkcs12.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/pkcs7.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/poly1305.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/ripemd.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/sakke.c)
    #zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/selftest.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/signature.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/siphash.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/sp_dsp32.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/sp_int.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/srp.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/tfm.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/wc_dsp.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/wc_encrypt.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/wc_keystore.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/wc_pkcs11.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/wc_port.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/wolfevent.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/wolfmath.c)

    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/port/psa/psa.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/port/psa/psa_aes.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/port/psa/psa_hash.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/port/psa/psa_pkcbs.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/port/st/stm32.c)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfcrypt/src/port/realtek/rtl8735b.c)

    if(CONFIG_WOLFCRYPT_ASM)
      if(CONFIG_WOLFCRYPT_ARM_SYMMETRIC_ASM)
        foreach(f aes-asm_c chacha-asm_c mlkem-asm_c poly1305-asm_c sha256-asm_c
                  sha3-asm_c sha512-asm_c curve25519_c)
          if(NOT (WOLF_BOUNDARY_ASM AND f MATCHES "^(aes|mlkem|sha256|sha3|sha512)-|^curve25519"))
            zephyr_library_sources(${WOLF_ARM_ASM_DIR}/${WOLF_ARM_ASM_PREFIX}-${f}.c)
          endif()
        endforeach()
      elseif(CONFIG_X86_64)
        # fe_x25519_asm.S, wc_mlkem_asm.S and wc_mldsa_asm.S are here because
        # curve25519.c, wc_mlkem_poly.c and wc_mldsa.c all take the Intel path
        # whenever USE_INTEL_SPEEDUP is set, so leaving one out is a link error
        # the moment an application enables that algorithm. Each is guarded by
        # its own feature macro, so it costs an empty object when it is off.
        # The AES sources are not here: everything they define is an _aesni
        # entry point, and their callers sit behind WOLFSSL_AESNI, which this
        # module does not define.
        foreach(f sha256_asm sha512_asm sha3_asm chacha_asm poly1305_asm
                  fe_x25519_asm wc_mlkem_asm wc_mldsa_asm)
          if(NOT WOLF_BOUNDARY_ASM OR f MATCHES "^(chacha|poly1305)_asm$")
            zephyr_library_sources(${WOLF_SRC}/${f}.S)
          endif()
        endforeach()
      endif()
    endif()

    zephyr_library_link_libraries(wolfSSL)

        target_compile_definitions(wolfSSL INTERFACE WOLFSSL_ZEPHYR)
        target_compile_definitions(wolfSSL INTERFACE WOLFSSL_USER_SETTINGS)

    if(NOT CONFIG_WOLFSSL_NO_HAVE_MIN_MAX AND
       (KERNEL_VERSION_MAJOR GREATER_EQUAL 5 OR
        (KERNEL_VERSION_MAJOR EQUAL 4 AND
         KERNEL_VERSION_MINOR GREATER_EQUAL 3)))
      target_compile_definitions(wolfSSL INTERFACE
        WOLFSSL_HAVE_MIN
        WOLFSSL_HAVE_MAX)
    endif()
    if(CONFIG_WOLFSSL_DEBUG)
      target_compile_definitions(wolfSSL INTERFACE DEBUG_WOLFSSL)
      zephyr_library_compile_options(-g3 -O0)
    endif()
  else()
    assert(CONFIG_WOLFSSL_LIBRARY "wolfSSL was enabled, but neither BUILTIN or LIBRARY was selected.")

    # NB: CONFIG_WOLFSSL_LIBRARY is not regression tested and is
    # therefore susceptible to bit rot

    target_include_directories(wolfSSL INTERFACE
        ${CONFIG_WOLFSSL_INSTALL_PATH}
        )

    zephyr_link_libraries(
      wolfssl_external
      -L${CONFIG_WOLFSSL_INSTALL_PATH}
      gcc
      )
    # Lib wolfssl depends on libgcc so to allow
    # wolfssl to link with gcc we need to ensure it is placed
    # after wolfssl_external on the linkers command line.
  endif()

  zephyr_link_libraries(wolfSSL)

endif()
